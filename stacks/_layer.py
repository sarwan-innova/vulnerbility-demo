"""
Helper to build the shared Lambda layer so the common modules land at
/opt/python (the path handlers import from).

A Lambda layer must place Python libraries under a top-level `python/` folder.
`Code.from_asset("lambda/common")` would put the files at the layer ROOT
(/opt/*), so `import store` from /opt/python fails at runtime (500).

This builds the asset with LOCAL bundling (no Docker): it copies
lambda/common/*.py into a `python/` subdir of the asset output, giving
/opt/python/store.py etc.
"""

import os
import shutil

from aws_cdk import BundlingOptions, DockerImage, ILocalBundling, aws_lambda as lambda_
import jsii

COMMON_SRC = "lambda/common"


@jsii.implements(ILocalBundling)
class _CopyCommonLocally:
    """Local bundler: copy lambda/common/*.py -> <output>/python/ (no Docker)."""

    def try_bundle(self, output_dir, *, image=None, **kwargs):
        target = os.path.join(output_dir, "python")
        os.makedirs(target, exist_ok=True)
        src = os.path.abspath(COMMON_SRC)
        for name in os.listdir(src):
            if name.endswith(".py"):
                shutil.copy2(os.path.join(src, name), os.path.join(target, name))
        return True


DEPS_SRC = "lambda_deps"


@jsii.implements(ILocalBundling)
class _PipInstallLocally:
    """Local bundler: pip-install lambda_deps/requirements.txt for the Lambda
    platform (manylinux x86_64, CPython 3.12) into <output>/python (no Docker)."""

    def try_bundle(self, output_dir, *, image=None, **kwargs):
        import subprocess
        import sys
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet",
                        "-r", os.path.join(os.path.abspath(DEPS_SRC), "requirements.txt"),
                        "--target", os.path.join(output_dir, "python"),
                        "--platform", "manylinux2014_x86_64", "--implementation", "cp",
                        "--python-version", "3.12", "--only-binary=:all:"], check=True)
        return True


def deps_layer_code():
    """Layer with third-party packages (the Anthropic SDK for the AI fix Lambda)."""
    return lambda_.Code.from_asset(
        DEPS_SRC,
        bundling=BundlingOptions(
            image=DockerImage.from_registry("public.ecr.aws/sam/build-python3.12"),
            local=_PipInstallLocally(),
            command=["bash", "-c", "pip install -r requirements.txt -t /asset-output/python"],
        ),
    )


def common_layer_code():
    """Return a Code asset where the common modules sit under python/."""
    return lambda_.Code.from_asset(
        COMMON_SRC,
        bundling=BundlingOptions(
            image=DockerImage.from_registry("public.ecr.aws/sam/build-python3.12"),
            local=_CopyCommonLocally(),
            command=[
                "bash", "-c",
                "mkdir -p /asset-output/python && cp /asset-input/*.py /asset-output/python/",
            ],
        ),
    )
