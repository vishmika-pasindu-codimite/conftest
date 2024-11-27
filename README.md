
# Conftest Policies

## Directory Structure

The repository is organized into the following directories:

### **Docker/**
  Contains policies for validating Dockerfiles, such as:
  - Preventing the `USER` instruction from being set to `root`.

---

### **Kubernetes/**

The `Kubernetes/` directory contains policies for validating Kubernetes manifests, ensuring they adhere to security and configuration best practices. These policies enforce the following key requirements:

- **Prevent Pods from Running as Root**:
  - Ensures that all containers in a Deployment or Pod run as non-root users by checking the `runAsNonRoot` property in the `securityContext`.

- **Mandatory Security Context Configuration**:
  - Requires the use of `securityContext` to explicitly define:
    - `runAsUser`: Specifies a non-root user ID for the container.
    - `runAsGroup`: Specifies a group ID for the container processes.
    - `fsGroup`: Ensures proper permissions for shared storage volumes.

- **Disable Privilege Escalation**:
  - Ensures the `allowPrivilegeEscalation` property is set to `false` for all containers, reducing the risk of elevated privileges inside the container.

- **Drop Unnecessary Capabilities**:
  - Ensures all Linux capabilities are dropped by default (`capabilities.drop: ["ALL"]`), following the principle of least privilege.

- **Read-Only Root Filesystem**:
  - Ensures that containers use a read-only root filesystem to prevent unnecessary write access, reducing the impact of potential attacks.

- **Disable Privileged Containers**:
  - Ensures the `privileged` property is set to `false` to restrict access to the host system.

- **Enforce Seccomp Profiles**:
  - Requires containers to use the `RuntimeDefault` seccomp profile, which restricts unnecessary system calls and improves runtime security.

- **Restrict Host Network Usage**:
  - Ensures that `hostNetwork` is explicitly set to `false`, preventing containers from accessing the host network.

- **Disable Automatic Mounting of Service Account Tokens**:
  - Requires `automountServiceAccountToken` to be set to `false`, reducing the risk of token misuse.
---

### Purpose
These policies ensure that Kubernetes workloads are deployed securely, following industry best practices. They help to:
- Prevent privilege escalation.
- Reduce the attack surface of workloads.
- Enforce consistency in security settings across teams.
