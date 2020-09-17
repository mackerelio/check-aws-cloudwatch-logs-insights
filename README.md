# check-aws-cloudwatch-logs-insights

## Description
Checks Amazon CloudWatch Logs using CloudWatch Logs Insights.

## Synopsis
```
check-aws-cloudwatch-logs-insights --log-group-name /aws/lambda/sample_log_group --query "filter @message =~ /error/" --critical-over 10 --warning-over 5
```

## Required IAM policy
TODO: Document which IAM policies are necessasry.


## Setting for mackerel-agent

If there are no problems in the execution result, add a setting in mackerel-agent.conf .

```
[plugin.checks.aws-cloudwatch-logs-sample]
command = ["check-aws-cloudwatch-logs-insights", "--log-group-name", "/aws/lambda/sample_log_group", "--query", "filter @message =~ /error/", "--critical-over", "10", "--warning-over", "5"]
```

## Usage
### Options

```
      --log-group-name=LOG-GROUP-NAME                    Log group name
  -f, --filter=FILTER                                    Filter expression to use search logs (TODO: not implemented yet. `--query` exists instead)
  -w, --warning-over=WARNING                             Trigger a warning if matched lines is over a number
  -c, --critical-over=CRITICAL                           Trigger a critical if matched lines is over a number
  -s, --state-dir=DIR                                    Dir to keep state files under (TODO: not working yet)
  -r, --return                                           Output matched lines (TODO: not implemented yet)
```

The plugin uses the instance profile if possible, or you can configure `AWS_PROFILE` or `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` and `AWS_REGION` environment variables in the `env` settings.

You can specify `--log-group-name` options multiple times, like `--log-group-name=/some/log/group --log-group-name=/another/log/group`.

#### `--filter` option
TODO: not implemented yet!!!
The expression specified by `--filter` will be used in the query for CloudWatch Logs Insights.  You can use one `filter` query command, or multiple query commands combined with `|`.  The query syntax is described in https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html.

Please note that using other than `parse`, `sort`, or `filter` commands will cause unexpected results.

Here are some examples.

```shell
check-aws-cloudwatch-logs-insights --filter='filter @message =~ /error/' ... # will search logs which contains "error"
```

```shell
check-aws-cloudwatch-logs-insights --filter='filter level = "error"' ... # will search JSON logs which has "level" fields and the value contains "error"
```

```shell
check-aws-cloudwatch-logs-insights --filter='filter @logStream = "app-container" | filter @message =~ /ohno/' ... # will search logs which contains "ohno" and its logStream name contains "app-container"
```
