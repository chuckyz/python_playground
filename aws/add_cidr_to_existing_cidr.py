#!/usr/bin/env python
import boto3, argparse


def add_cidr_ingress(old_cidr, new_cidr):
    """
	Adds a new cidr ingress to all security groups matching
	with an existing cidr ingress
	"""
    client = boto3.client("ec2")
    # aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values="some.cidr/range"
    resp = client.describe_security_groups(
        Filters=[{"Name": "ip-permission.cidr", "Values": ["{}".format(old_cidr)]}]
    )

    sg_metadata = {}
    for rule in resp["SecurityGroups"]:
        sg_id = rule["GroupId"]
        ports = []
        for ingress in rule["IpPermissions"]:
            if old_cidr in [x["CidrIp"] for x in ingress["IpRanges"]]:
                ports.append(
                    [
                        ingress.get("IpProtocol"),
                        ingress.get("FromPort", "-1"),
                        ingress.get("ToPort", "-1"),
                    ]
                )
        sg_metadata[sg_id] = ports

    for sg_id in sg_metadata.keys():
        ip_permissions = [
            {
                "IpProtocol": x[0],
                "FromPort": x[1],
                "ToPort": x[2],
                "IpRanges": [{"CidrIp": new_cidr}],
            }
            for x in sg_metadata[sg_id]
        ]
        print(
            'CidrIp="{}",GroupId="{}",IpPermissions={}'.format(
                new_cidr, sg_id, ip_permissions
            )
        )
        # for port in ports:
        # 	resp = client.authorize_security_group_ingress(
        # 			CidrIp='{}'.format(new_cidr),
        # 		)
    return sg_metadata.keys()


def main():
    parser = argparse.ArgumentParser(
        description="add new cidr group to aws security groups with an existing cidr group"
    )
    parser.add_argument("-o", "--old_cidr", required=True)
    parser.add_argument("-n", "--new_cidr", required=True)
    args = parser.parse_args()
    try:
        sgs_modified = add_cidr_ingress(args.old_cidr, args.new_cidr)
    except Exception as e:
        raise
        # for sg in sgs_modified:
        # 	print("Added {} to {}".format(args.new_cidr, sg))


if __name__ == "__main__":
    main()
