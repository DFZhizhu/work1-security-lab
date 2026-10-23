# Configuration-level mitigation files

`struts-actionchaining.xml` is a modified version of the Vulhub S2-057 training configuration. It explicitly defines a non-wildcard namespace and the redirect namespace. Copy it over `vulhub/struts2/s2-057/struts-actionchaining.xml` while the service is stopped, then restart.

The overlay Compose file is optional and references that local XML; the original Vulhub Compose file already mounts the same path. This mitigation only addresses the reproduced namespace-based route and **does not replace vendor patching**. Apache recommends a supported patched Struts release (2.3.35/2.5.17 were the initial fixes). Validate the benign `233*233` payload against the original and mitigated environment, and regression-test legitimate pages.
