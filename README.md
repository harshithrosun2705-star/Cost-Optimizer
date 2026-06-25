# AWS Cost Optimization & Governance Monitoring Platform

A serverless AWS cost optimization project that automatically scans multiple AWS regions, identifies idle or cost-risk resources, estimates monthly savings, and sends a professional email report using Amazon SES.

## Features

- Multi-region AWS resource scanning
- EventBridge scheduled automation
- AWS Lambda based monitoring engine
- CloudWatch Logs for execution tracking
- Amazon SES email reporting
- AWS Cost Explorer integration
- Governance-aware recommendations using AWS tags

## Resources Monitored

- Stopped EC2 instances
- Attached EBS cost for stopped EC2
- Unattached EBS volumes
- Old EBS snapshots
- Unused Elastic IPs
- NAT Gateways
- Idle Load Balancers
- High daily service cost

## AWS Services Used

- AWS Lambda
- Amazon EventBridge
- Amazon CloudWatch
- Amazon SES
- AWS Cost Explorer
- Amazon EC2
- Elastic Load Balancing
- IAM

## Architecture

```text
EventBridge Schedule
        ↓
AWS Lambda
        ↓
Multi-Region AWS Resource Scan
        ↓
Cost & Governance Analysis
        ↓
CloudWatch Logs
        ↓
SES Email Report
