#!/usr/bin/env python
import boto3, argparse
import botocore.exceptions

def get_sg_metadata(sgs,old_cidr):
    """
    Get some metadata from SGs for use
    """
    sg_metadata = {}
    for rule in sgs:
        sg_id = rule["GroupId"]
        ports = []
        for ingress in rule["IpPermissions"]:
            if old_cidr in [x["CidrIp"] for x in ingress["IpRanges"]]:
                ports.append(
                    [
                        ingress.get("IpProtocol"),
                        ingress.get("FromPort", -1),
                        ingress.get("ToPort", -1),
                    ]
                )
        sg_metadata[sg_id] = ports
    return sg_metadata


def add_cidr_ingress(old_cidr, new_cidr):
    """
	Adds a new cidr ingress to all security groups matching
	with an existing cidr ingress
	"""
    client = boto3.client("ec2")
    # aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values="some.cidr/range"
    resp = client.describe_security_groups(
        # ,{"Name": "vpc-id", "Values": ["vpc-1234"]}
        Filters=[{"Name": "ip-permission.cidr", "Values": ["{}".format(old_cidr)]}]
    )

    sg_metadata = get_sg_metadata(resp["SecurityGroups"],old_cidr)

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
        # print(
        #     'GroupId="{}",IpPermissions={}'.format(
        #         sg_id, ip_permissions
        #     )
        # )
        try:
            resp = client.authorize_security_group_ingress(
            		GroupId='{}'.format(sg_id),
                    IpPermissions=ip_permissions
            	)
            print("{} added to {}".format(new_cidr, sg_id))
        except botocore.exceptions.ClientError:
            print("{} already allowed to {}".format(new_cidr, sg_id))
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


if __name__ == "__main__":
    main()
