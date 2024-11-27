package main

import data.namespaces.dev

deny[msg] {
    input.kind = "Deployment"
    not input.spec.template.spec.hostNetwork == false
    msg = "Deployments must have hostNetwork set to false"
}

deny[msg] {
    input.kind == "Deployment"
    not input.spec.template.spec.automountServiceAccountToken == false
    msg = "Deployments must have automountServiceAccountToken set to false"
}

deny[msg] {
    input.kind = "Deployment"
    not input.spec.template.spec.securityContext.runAsNonRoot == true
    msg = "Containers must not run as root"
}

deny[msg] {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext.fsGroup
    msg = "Deployments must specify a fsGroup in the securityContext"
}

deny[msg] {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext.runAsGroup
    msg = "Deployments must specify runAsGroup in the securityContext"
}

deny[msg] {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext.runAsUser
    msg = "Deployments must specify runAsUser in the securityContext"
}

deny[msg] {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext.seccompProfile.type == "RuntimeDefault"
    msg = "Deployments must have seccompProfile type set to RuntimeDefault"
}

deny[msg] {
    input.kind == "Deployment"
    some i
    container := input.spec.template.spec.containers[i]
    not container.securityContext.allowPrivilegeEscalation == false
    msg = "Containers must have allowPrivilegeEscalation set to false in the securityContext"
}

deny[msg] {
    input.kind == "Deployment"
    some i
    container := input.spec.template.spec.containers[i]
    not container.securityContext.readOnlyRootFilesystem == true
    msg = "Containers must have readOnlyRootFilesystem set to true in the securityContext"
}

deny[msg] {
    input.kind == "Deployment"
    some i
    container := input.spec.template.spec.containers[i]
    not container.securityContext.privileged == false
    msg = "Containers must have privileged set to false in the securityContext"
}

deny[msg] {
    input.kind == "Deployment"
    some i
    container := input.spec.template.spec.containers[i]
    
    # Ensure capabilities.drop is exactly ["ALL"]
    not container.securityContext.capabilities.drop == ["ALL"]
    msg = "Containers must drop all capabilities by setting capabilities.drop: ['ALL'] in the securityContext"
}


