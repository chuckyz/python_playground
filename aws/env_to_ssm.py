import boto3, os, logging
from time import sleep

"""
Setup:
Just run `aws s3 sync s3://... sync/`
Doing that with boto3 is super convoluted.
"""


def get_env_files(dir):
    env_files = []
    if os.name == "nt":
        sep = "\\"
    if os.name == "posix":
        sep = "/"
    for path, name, file in os.walk("sync"):
        if file == [".env"]:
            env_files.append(path + sep + file[0])
    return env_files


def main():
    ssm_client = boto3.client("ssm")
    env_files = get_env_files("sync")

    parsed_env_files = {}

    for env_file in env_files:
        f = open(env_file, mode="r")
        env_output = []
        for line in f.readlines():
            if line != "" and line != "\n" and line[0] != "#":
                env_output.append(line.strip())
        f.close()
        parsed_env_files[env_file] = env_output

    for file in parsed_env_files.keys():
        # sleep(20) # There are unpublished get/set limits for SSM Parameter Store
        if "\\" in file:
            parambase = "/".join([""] + file.split("\\")[1:-1] + [""])
        else:
            parambase = "/".join([""] + file.split("/")[1:-1] + [""])
        for parameter in parsed_env_files.get(file):
            paramkey, paramvalue = parameter.split("=", maxsplit=1)
            parampath = parambase + paramkey
            if paramvalue == "":
                paramvalue = "UNSET"
            if "{{" in paramvalue:
                paramvalue = paramvalue.replace("{{", "LEFT_MUSTACHE").replace(
                    "}}", "RIGHT_MUSTACHE"
                )
            # sleep(1) # There are unpublished get/set limits for SSM Parameter Store
            print("PUTing {}".format(parampath))
            ssm_client.put_parameter(
                Name=parampath, Value=paramvalue, Type="SecureString", Overwrite=True
            )


if __name__ == "__main__":
    main()
