"""
In-memory ECR tags for local runs: just the calls the gate makes
(batch_get_image / put_image / batch_delete_image) on image digests the local
build "pushed".
"""

import threading


class MockEcr:
    def __init__(self):
        self.tags = {}           # (repo, tag) -> digest
        self._lock = threading.RLock()

    def push(self, repo, tag, digest):
        with self._lock:
            self.tags[(repo, tag)] = digest

    def batch_get_image(self, repositoryName, imageIds, acceptedMediaTypes=None):
        digest = imageIds[0].get("imageDigest")
        known = digest in self.tags.values()
        return {"images": [{"imageId": {"imageDigest": digest},
                            "imageManifest": f'{{"digest": "{digest}"}}',
                            "imageManifestMediaType": "application/vnd.oci.image.manifest.v1+json"}]
                if known else []}

    def put_image(self, repositoryName, imageManifest, imageTag, imageManifestMediaType=None):
        import json
        with self._lock:
            self.tags[(repositoryName, imageTag)] = json.loads(imageManifest)["digest"]
        return {"image": {"imageId": {"imageTag": imageTag}}}

    def batch_delete_image(self, repositoryName, imageIds):
        with self._lock:
            for i in imageIds:
                self.tags.pop((repositoryName, i.get("imageTag")), None)
        return {"imageIds": imageIds, "failures": []}
