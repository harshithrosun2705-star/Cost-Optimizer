import boto3
import os
from datetime import datetime, timedelta, timezone

SENDER_EMAIL = os.environ["SENDER_EMAIL"]
RECEIVER_EMAIL = os.environ["RECEIVER_EMAIL"]
SES_REGION = os.environ.get("SES_REGION", "us-east-1")
COST_THRESHOLD = float(os.environ.get("COST_THRESHOLD", "1"))
SNAPSHOT_AGE_DAYS = int(os.environ.get("SNAPSHOT_AGE_DAYS", "60"))

EBS_COST_PER_GB_MONTH = 0.08
SNAPSHOT_COST_PER_GB_MONTH = 0.05
ELASTIC_IP_COST_MONTH = 3.60
NAT_GATEWAY_COST_MONTH = 32.00
LOAD_BALANCER_COST_MONTH = 18.00

ses = boto3.client("ses", region_name=SES_REGION)
ce = boto3.client("ce", region_name="us-east-1")


def get_all_regions():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    return [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]


def tags_to_dict(tags):
    if not tags:
        return {}
    return {tag["Key"]: tag["Value"] for tag in tags}


def get_tag_value(tag_dict, key):
    for k, v in tag_dict.items():
        if k.lower() == key.lower():
            return v
    return "Not Tagged"


def get_environment(tag_dict):
    env = get_tag_value(tag_dict, "Environment")
    if env == "Not Tagged":
        env = get_tag_value(tag_dict, "Env")
    return env

def get_governance_status(tag_dict):
    env = get_environment(tag_dict).lower()

    if env in ["prod", "production","product","pd"]:
        return "🟥 Production Resource"

    elif env in ["dev", "development"]:
        return "🟩 Development Resource"

    elif env in ["test", "testing", "uat", "staging"]:
        return "🟨 Test/UAT Resource"

    elif env == "not tagged":
        return "⚪ Untagged Resource (Needs Attention)"

    else:
        return "🟦 Custom Environment"

def build_tag_text(tag_dict):

    env = get_environment(tag_dict)
    owner = get_tag_value(tag_dict, "Owner")
    app = get_tag_value(tag_dict, "Application")

    governance = get_governance_status(tag_dict)

    return (
        f"Governance Status: {governance} | "
        f"Environment: {env} | "
        f"Owner: {owner} | "
        f"Application: {app}"
    )

def get_tag_based_action(base_action, tag_dict):
    env = get_environment(tag_dict).lower()
    owner = get_tag_value(tag_dict, "Owner")

    if env in ["prod", "production"]:
        return (
            "Production-tagged resource. Do NOT delete directly. "
            f"Review with owner/team first. Owner: {owner}. Base action: {base_action}"
        )

    if env in ["dev", "development", "test", "testing", "uat", "staging"]:
        return (
            "Non-production resource. Safe to review for cleanup after confirming with owner. "
            f"Owner: {owner}. Base action: {base_action}"
        )

    return (
        "Environment tag missing or unclear. Review manually before cleanup. "
        f"Owner: {owner}. Base action: {base_action}"
    )


def add_finding(findings, severity, region, resource_type, resource_id, details, action, saving):
    findings.append({
        "severity": severity,
        "region": region,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details,
        "action": action,
        "saving": saving
    })


def check_unattached_ebs(region):
    findings = []
    ec2 = boto3.client("ec2", region_name=region)

    for v in ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}])["Volumes"]:
        tag_dict = tags_to_dict(v.get("Tags", []))
        tag_text = build_tag_text(tag_dict)

        saving = v["Size"] * EBS_COST_PER_GB_MONTH
        severity = "HIGH" if v["Size"] >= 100 else "MEDIUM"

        base_action = "Delete the volume if it is not required."
        action = get_tag_based_action(base_action, tag_dict)

        add_finding(
            findings,
            severity,
            region,
            "Unattached EBS Volume",
            v["VolumeId"],
            f"Size: {v['Size']} GB | AZ: {v['AvailabilityZone']} | Tags: {tag_text}",
            action,
            saving
        )

    return findings


def check_stopped_instances(region):
    findings = []
    ec2 = boto3.client("ec2", region_name=region)

    response = ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
    )

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            tag_dict = tags_to_dict(instance.get("Tags", []))
            tag_text = build_tag_text(tag_dict)

            total_storage = 0

            for device in instance.get("BlockDeviceMappings", []):
                if "Ebs" in device:
                    volume_id = device["Ebs"]["VolumeId"]
                    volume = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
                    total_storage += volume["Size"]

            saving = total_storage * EBS_COST_PER_GB_MONTH
            severity = "HIGH" if total_storage >= 20 else "MEDIUM"

            base_action = "Terminate instance and delete attached EBS if no longer required."
            action = get_tag_based_action(base_action, tag_dict)

            add_finding(
                findings,
                severity,
                region,
                "Stopped EC2 Instance",
                instance["InstanceId"],
                f"Type: {instance['InstanceType']} | Attached EBS: {total_storage} GB | Tags: {tag_text}",
                action,
                saving
            )

    return findings


def check_old_snapshots(region):
    findings = []
    ec2 = boto3.client("ec2", region_name=region)
    cutoff = datetime.now(timezone.utc) - timedelta(days=SNAPSHOT_AGE_DAYS)

    for s in ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]:
        if s["StartTime"] < cutoff:
            tag_dict = tags_to_dict(s.get("Tags", []))
            tag_text = build_tag_text(tag_dict)

            saving = s["VolumeSize"] * SNAPSHOT_COST_PER_GB_MONTH

            base_action = "Delete snapshot if backup is not required."
            action = get_tag_based_action(base_action, tag_dict)

            add_finding(
                findings,
                "LOW",
                region,
                "Old EBS Snapshot",
                s["SnapshotId"],
                f"Created: {s['StartTime'].date()} | Size: {s['VolumeSize']} GB | Tags: {tag_text}",
                action,
                saving
            )

    return findings


def check_unused_elastic_ips(region):
    findings = []
    ec2 = boto3.client("ec2", region_name=region)

    for ip in ec2.describe_addresses()["Addresses"]:
        if "InstanceId" not in ip and "NetworkInterfaceId" not in ip:
            tag_dict = tags_to_dict(ip.get("Tags", []))
            tag_text = build_tag_text(tag_dict)

            resource_id = ip.get("AllocationId", ip.get("PublicIp", "Unknown"))

            base_action = "Release the Elastic IP if not required."
            action = get_tag_based_action(base_action, tag_dict)

            add_finding(
                findings,
                "HIGH",
                region,
                "Unused Elastic IP",
                resource_id,
                f"Public IP: {ip.get('PublicIp', 'N/A')} | Tags: {tag_text}",
                action,
                ELASTIC_IP_COST_MONTH
            )

    return findings


def check_nat_gateways(region):
    findings = []
    ec2 = boto3.client("ec2", region_name=region)

    response = ec2.describe_nat_gateways(
        Filter=[{"Name": "state", "Values": ["available"]}]
    )

    for nat in response["NatGateways"]:
        tag_dict = tags_to_dict(nat.get("Tags", []))
        tag_text = build_tag_text(tag_dict)

        base_action = "Review NAT Gateway usage and delete if it is not required."
        action = get_tag_based_action(base_action, tag_dict)

        add_finding(
            findings,
            "HIGH",
            region,
            "NAT Gateway",
            nat["NatGatewayId"],
            f"VPC: {nat.get('VpcId', 'N/A')} | Subnet: {nat.get('SubnetId', 'N/A')} | State: available | Tags: {tag_text}",
            action,
            NAT_GATEWAY_COST_MONTH
        )

    return findings


def check_idle_load_balancers(region):
    findings = []
    elb = boto3.client("elbv2", region_name=region)

    try:
        load_balancers = elb.describe_load_balancers()["LoadBalancers"]
    except Exception:
        return findings

    for lb in load_balancers:
        lb_arn = lb["LoadBalancerArn"]
        lb_name = lb["LoadBalancerName"]
        lb_type = lb["Type"]

        tag_dict = {}

        try:
            tag_response = elb.describe_tags(ResourceArns=[lb_arn])
            tag_dict = tags_to_dict(tag_response["TagDescriptions"][0].get("Tags", []))
        except Exception:
            tag_dict = {}

        tag_text = build_tag_text(tag_dict)

        target_groups = elb.describe_target_groups(LoadBalancerArn=lb_arn)["TargetGroups"]

        base_action = "Delete the load balancer if it is not required."
        action = get_tag_based_action(base_action, tag_dict)

        if len(target_groups) == 0:
            add_finding(
                findings,
                "HIGH",
                region,
                "Idle Load Balancer",
                lb_name,
                f"Type: {lb_type} | No target groups attached | Tags: {tag_text}",
                action,
                LOAD_BALANCER_COST_MONTH
            )

        else:
            total_targets = 0

            for tg in target_groups:
                health = elb.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
                total_targets += len(health["TargetHealthDescriptions"])

            if total_targets == 0:
                add_finding(
                    findings,
                    "MEDIUM",
                    region,
                    "Idle Load Balancer",
                    lb_name,
                    f"Type: {lb_type} | Target groups exist but no registered targets | Tags: {tag_text}",
                    action,
                    LOAD_BALANCER_COST_MONTH
                )

    return findings


def check_daily_cost():
    findings = []
    today = datetime.utcnow().date()
    yesterday = today - timedelta(days=1)

    response = ce.get_cost_and_usage(
        TimePeriod={"Start": str(yesterday), "End": str(today)},
        Granularity="DAILY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}]
    )

    for result in response["ResultsByTime"]:
        for group in result["Groups"]:
            service = group["Keys"][0]
            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
            unit = group["Metrics"]["UnblendedCost"]["Unit"]

            if amount >= COST_THRESHOLD:
                add_finding(
                    findings,
                    "MEDIUM",
                    "ACCOUNT-WIDE",
                    "High Daily Service Cost",
                    service,
                    f"Yesterday cost: {amount:.2f} {unit}",
                    "Review this service usage in AWS Cost Explorer.",
                    0
                )

    return findings


def build_summary(findings, region_count):
    summary = {
        "regions": region_count,
        "stopped_ec2": 0,
        "unused_ebs": 0,
        "old_snapshots": 0,
        "unused_elastic_ip": 0,
        "nat_gateways": 0,
        "idle_load_balancers": 0,
        "high_daily_cost": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "saving": 0
    }

    for item in findings:
        summary["saving"] += item["saving"]

        if item["severity"] == "HIGH":
            summary["high"] += 1
        elif item["severity"] == "MEDIUM":
            summary["medium"] += 1
        elif item["severity"] == "LOW":
            summary["low"] += 1

        if item["resource_type"] == "Stopped EC2 Instance":
            summary["stopped_ec2"] += 1
        elif item["resource_type"] == "Unattached EBS Volume":
            summary["unused_ebs"] += 1
        elif item["resource_type"] == "Old EBS Snapshot":
            summary["old_snapshots"] += 1
        elif item["resource_type"] == "Unused Elastic IP":
            summary["unused_elastic_ip"] += 1
        elif item["resource_type"] == "NAT Gateway":
            summary["nat_gateways"] += 1
        elif item["resource_type"] == "Idle Load Balancer":
            summary["idle_load_balancers"] += 1
        elif item["resource_type"] == "High Daily Service Cost":
            summary["high_daily_cost"] += 1

    return summary


def build_report(findings, summary):
    lines = []

    lines.append("=" * 70)
    lines.append("AWS MULTI-REGION COST OPTIMIZATION REPORT - VERSION 6")
    lines.append("=" * 70)
    lines.append(f"Generated At                 : {datetime.utcnow()} UTC")
    lines.append(f"Snapshot Age Threshold        : {SNAPSHOT_AGE_DAYS} days")
    lines.append("")

    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 70)
    lines.append(f"Regions Scanned               : {summary['regions']}")
    lines.append(f"Stopped EC2 Instances          : {summary['stopped_ec2']}")
    lines.append(f"Unattached EBS Volumes         : {summary['unused_ebs']}")
    lines.append(f"Old EBS Snapshots              : {summary['old_snapshots']}")
    lines.append(f"Unused Elastic IPs             : {summary['unused_elastic_ip']}")
    lines.append(f"NAT Gateways                   : {summary['nat_gateways']}")
    lines.append(f"Idle Load Balancers            : {summary['idle_load_balancers']}")
    lines.append(f"High Daily Cost Services       : {summary['high_daily_cost']}")
    lines.append(f"High Severity Findings         : {summary['high']}")
    lines.append(f"Medium Severity Findings       : {summary['medium']}")
    lines.append(f"Low Severity Findings          : {summary['low']}")
    lines.append(f"Estimated Monthly Saving       : ${summary['saving']:.2f}")
    lines.append("")

    lines.append("DETAILED FINDINGS")
    lines.append("-" * 70)

    if not findings:
        lines.append("No cost optimization issues found.")
        return "\n".join(lines)

    for item in findings:
        lines.append(f"[{item['severity']}] {item['resource_type']}")
        lines.append(f"Region                     : {item['region']}")
        lines.append(f"Resource                   : {item['resource_id']}")
        lines.append(f"Details                    : {item['details']}")
        lines.append(f"Recommended Action          : {item['action']}")
        lines.append(f"Estimated Monthly Saving    : ${item['saving']:.2f}")
        lines.append("-" * 70)

    return "\n".join(lines)

def send_email(report):
    html_report = report.replace("\n", "<br>")

    html_body = f"""
    <html>
    <body style="margin:0; padding:0; background:#f3f4f6; font-family:Arial, sans-serif;">
      <div style="max-width:900px; margin:30px auto; background:#ffffff; border-radius:12px; overflow:hidden; border:1px solid #e5e7eb;">

        <div style="background:#232f3e; padding:24px; text-align:center;">
          <h1 style="color:#ffffff; margin:0; font-size:26px;">AWS Cost Optimization Dashboard</h1>
          <p style="color:#ff9900; margin:8px 0 0;">Multi-Region Cost, Governance & Resource Monitoring</p>
        </div>

        <div style="padding:24px;">
          <table width="100%" cellpadding="12" cellspacing="0" style="border-collapse:collapse;">
            <tr>
              <td style="background:#ecfdf5; border-radius:10px; text-align:center;">
                <h2 style="margin:0; color:#047857;">Estimated Savings</h2>
                <p style="font-size:28px; font-weight:bold; margin:8px 0;">Check Summary Below</p>
              </td>
              <td style="background:#eff6ff; border-radius:10px; text-align:center;">
                <h2 style="margin:0; color:#1d4ed8;">Scan Scope</h2>
                <p style="font-size:22px; font-weight:bold; margin:8px 0;">All Enabled Regions</p>
              </td>
            </tr>
          </table>

          <br>

          <div style="background:#fff7ed; border-left:5px solid #f97316; padding:16px; border-radius:8px;">
            <h3 style="margin-top:0; color:#c2410c;">Executive Report</h3>
            <p style="margin:0; color:#374151;">
              This automated report identifies idle AWS resources, estimates monthly savings,
              and uses tags such as Environment, Owner, and Application for governance-aware recommendations.
            </p>
          </div>

          <br>

          <div style="background:#111827; color:#f9fafb; padding:20px; border-radius:10px;">
            <pre style="white-space:pre-wrap; font-family:Consolas, monospace; font-size:13px; line-height:1.6; margin:0;">
{report}
            </pre>
          </div>

          <br>

          <div style="background:#fef2f2; border-left:5px solid #dc2626; padding:16px; border-radius:8px;">
            <h3 style="margin-top:0; color:#991b1b;">Important Note</h3>
            <p style="margin:0; color:#374151;">
              Do not delete or terminate any resource directly. Review tags, owner details,
              and business impact before cleanup.
            </p>
          </div>
        </div>

        <div style="background:#f9fafb; padding:16px; text-align:center; color:#6b7280; font-size:12px;">
          Generated automatically by AWS Lambda, EventBridge, CloudWatch, SES, IAM, EC2 APIs, ELB APIs and Cost Explorer.
        </div>

      </div>
    </body>
    </html>
    """

    ses.send_email(
        Source=SENDER_EMAIL,
        Destination={"ToAddresses": [RECEIVER_EMAIL]},
        Message={
            "Subject": {"Data": "AWS Cost Optimization Dashboard Report"},
            "Body": {
                "Text": {"Data": report},
                "Html": {"Data": html_body}
            }
        }
    )

    ses.send_email(
        Source=SENDER_EMAIL,
        Destination={"ToAddresses": [RECEIVER_EMAIL]},
        Message={
            "Subject": {"Data": "AWS Cost Optimization Dashboard Report - Version 6"},
            "Body": {
                "Text": {"Data": report},
                "Html": {"Data": html_body}
            }
        }
    )


def lambda_handler(event, context):
    findings = []
    regions = get_all_regions()

    for region in regions:
        findings.extend(check_unattached_ebs(region))
        findings.extend(check_stopped_instances(region))
        findings.extend(check_old_snapshots(region))
        findings.extend(check_unused_elastic_ips(region))
        findings.extend(check_nat_gateways(region))
        findings.extend(check_idle_load_balancers(region))

    findings.extend(check_daily_cost())

    summary = build_summary(findings, len(regions))
    report = build_report(findings, summary)

    print(report)
    send_email(report)

    return {
        "statusCode": 200,
        "body": report
    }
