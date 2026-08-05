-- Registry credentials now live on the Image record and are resolved by the
-- image proxy, which never hands them to a workload cluster. There is nothing
-- left for an operator to attach, and no way for two attachments to disagree
-- about the same registry.
DROP TABLE IF EXISTS image_pull_secrets;
