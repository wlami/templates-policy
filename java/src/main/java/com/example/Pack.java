package com.example;

import com.pulumi.policy.EnforcementLevel;
import com.pulumi.policy.PolicyPack;
import com.pulumi.policy.PolicyPackArgs;
import com.pulumi.policy.ResourceValidationPolicy;

public class Pack {
  public static void main(String[] args) {
    PolicyPack.run("java",
        PolicyPackArgs.builder()
            .enforcementLevel(EnforcementLevel.ADVISORY)
            .policies(ResourceValidationPolicy.builder()
                .name("s3-no-public-read")
                .description("Prohibits setting the publicRead or publicReadWrite permission on AWS S3 bucket ACLs.")
                .enforcementLevel(EnforcementLevel.MANDATORY)
                .validate((rArgs, report) -> {
                  // The legacy `acl` property on aws:s3/bucket:Bucket is deprecated;
                  // ACLs now live on aws:s3/bucketAclV2:BucketAclV2 (and on
                  // aws:s3/bucketAcl:BucketAcl in older provider versions). Flag both.
                  if ("aws:s3/bucketAclV2:BucketAclV2".equals(rArgs.type())
                      || "aws:s3/bucketAcl:BucketAcl".equals(rArgs.type())) {
                    Object acl = rArgs.props().get("acl");
                    if ("public-read".equals(acl) || "public-read-write".equals(acl)) {
                      report.violation(
                          "Bucket ACL must not be public-read or public-read-write. "
                          + "Read more about ACLs here: "
                          + "https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html");
                    }
                  }
                })
                .build())
            .build(),
        args);
  }
}
