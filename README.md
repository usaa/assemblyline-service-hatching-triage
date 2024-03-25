# assemblyline-service-hatching-triage

[![Scheduled Tag and Build Workflow](https://github.com/usaa/assemblyline-service-hatching-triage/actions/workflows/scheduled-auto-build-workflow.yml/badge.svg)](https://github.com/usaa/assemblyline-service-hatching-triage/actions/workflows/scheduled-auto-build-workflow.yml)

Assemblyline v4 service for the Hatching Triage platform.

![](./al4-hatching-logo.jpg)

This Assemblyline service submits files to the Hatching Triage platform for analysis. It can be configured to point to
private or public instances.

```text
This service requires you to have your own API key and requires further configuration.

See the Configuration section.
```

## Execution

This service submits the file to the defined Hatching Triage system for analysis, waits for completion, and presents
the results.

### API Quota Usage

Understand that submitting the same file multiple times to Hatching will count against your service quota.
This should probably only be a concern if you regularly use the AL4 `Ignore Results Cache` submission parameter.

### Hatching Results

- If your VM profile with Hatching is configured to fake internet responses with an http 200 response, all resulting
communications, such as DNS lookups and http requests to domains will use the 100.64.0.0/10 IP space. See
[RFC 6598](https://datatracker.ietf.org/doc/html/rfc6598).

## Configuration

### Defining VM Profiles

This is a required step. It explains how to configure this AL4 service to map to Hatching's VM profiles.

First, create a VM `Profile` in the Hatching console for each VM you want to represent in AL4.
Note: While defining the profile in the Hatching console, if you select `Automatic` or the generic platform such as
`Windows` instead of a specific VM, such as `Windows 10`, it may run multiple VMs for a given submission. Each VM that
runs counts against your quota.

Next, add the Hatching VM profiles you want the user to see as an AL4 submission option to the `vm_profile` list under
`config.submission_params`. If the value `auto-detect-platform` is selected, it will use the
`config.vm_profile_auto_detect_map` to map to the appropriate profile.

In this example, each of the profiles listed are also configured in the Hatching console.
All except `auto-detect-platform`. That profile uses the functionality in this service to detect which profile to use.

```yaml
config:
  submission_params:

    - default: "auto-detect-platform"
      name: vm_profile
      type: list
      value: "auto-detect-platform"
      list: ["auto-detect-platform", "win-profile", "win-profile-2", "macos-profile", "linux-profile", "android-profile"]
```

Next, update the `config.vm_profile_autodetect_map` entries. This configuration is used when the `auto-detect-platform`
is selected during a submission. This service will determine the most likely platform and submit the file to the
Hatching VM profiles defined for that platform. You can add one or more Hatching profiles to each platform.

`vm_profile_autodetect_map` accepts the following keys: `windows, macos, linux, android, default`.

If you do not want a particular platform defined, just remove the key. If the user selects `auto-detect-platform` and
the platform detected is not actually configured in `vm_profile_autodetect_map`, then the default will be used.

```yaml
config:
  vm_profile_autodetect_map:
    windows: ["win-profile", "win-profile-2"]
    macos: ["macos-profile",]
    linux: ["linux-profile",]
    android: ["android-profile",]
    default: ["win-profile",]
```

### Service Configuration

| Name    | Description |
| ------- | ----------- |
| host_config.web_url | The web console's UI endpoint. |
| host_config.api_url | The API endpoint. |
| host_config.api_key | Your API key. |
| max_file_depth_short_circuit | See separate note. |
| vm_profile_autodetect_map | See Defining VM Profiles section. |

#### max_file_depth_short_circuit

At a max file-depth of X, do not fully run this service. i.e. skip submitting the file to the Hatching API.
If the submission indicates `ignore_dynamic_recursion_prevention=True`, it's possible for the dumped files being
downloaded from Hatching for a given submission, which are then added back to the pipeline for analysis, to cause
a never-ending recursive analysis loop. This would eat up a user's quota very quickly. This configuration will prevent
that situation by not allowing any files above the specified file depth from being submitted to Hatching service.

This is an imperfect solution as the service is not able to determine that `ignore_dynamic_recursion_prevention=True`
was used. So, if you have a submission that has extracted files X+1 layers deep in the hierarchy, it will not submit
to the Hatching service.

### Submission Parameters

| Name                           | Description                                                                  |
| ------------------------------ | ---------------------------------------------------------------------------- |
| analyze_extracted_memory_dumps | Indicates whether extracted memory dumps will be added back into the pipeline for analysis. |
| vm_profile                     | See Defining VM Profiles section. |

### Assemblyline System Safelist

The file at `al_config/hatching-system-safelist.yaml` contains suggested safelisted values that should be added to the
Assemblyline system safelist either by copy-and-pasting directly to the text editor on the page
`https://your-instance/admin/tag_safelist` or through the Assemblyline Client.

When using the UI, merge the values with your existing system-safelist instead of overwriting.

## Design Decisions

- A single generic heuristic is defined to handle all possible Hatching Signatures identified during analysis. Since Hatching is closed-source, there is no definitive list of all possible signatures to map to.
