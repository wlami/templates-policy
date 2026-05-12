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
                .description("Prohibits setting the publicRead or publicReadWrite permission on AWS S3 buckets.")
                .enforcementLevel(EnforcementLevel.MANDATORY)
                .validate((rArgs, report) -> {
                  if ("aws:s3/bucket:Bucket".equals(rArgs.type())) {
                    Object acl = rArgs.props().get("acl");
                    if ("public-read".equals(acl) || "public-read-write".equals(acl)) {
                      report.violation(
                          "You cannot set public-read or public-read-write on an S3 bucket. "
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
