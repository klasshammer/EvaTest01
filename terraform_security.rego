package terraform.authz

default allow := {
    "status": false,
    "reason": "El recurso no cumple con los requisitos de la política."
}

allow := result if {
    some i
    input.resource_changes[i].type == "aws_key_pair"
    input.resource_changes[i].change.after.public_key == "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDiuFUssdtHg8Y3rWGZFCSD58hSr4IqjFVKeid9d0G3bk7w99/AOyL/C45PnFodjOtD1eMndiCd40BqagdOYtKoieqlOTlmShrvE7N2A+MeaOP4CWLx7fj2MfekecPPFRAiMUCZk51SHxFr4oqX4Qhj8BkG1cG30p9QB+stfJKT3tUGczxUB1aor9qoLmPDTfaE4iSmNDscVmqQhX9jkppdzkg2ENh5cDO2EtLlHHxIodXLgetpWjBP68r90q/gwZV69XANcTWjZiZRyDmb9nIfQiZOO5C03FoG0GmTSZkAfvZdq7M2GsQSboln44VW/ukyQKFRVVepOCIHTaqcsjhV"
     # Condición B: Validar que existan Tags (la regla que tenías al final)
    resource_tags := input.resource_changes[_]
    resource_tags.change.after.tags["Name"]
    result := {
        "status": true,
        "reason": "El recurso cumple con la política y la clave pública es válida."
    }
}

# Regla corregida con 'if' y 'contains'
deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    instance_type := resource.change.after.instance_type
    instance_type != "t2.micro"
    
    msg := sprintf("Tipo de instancia no permitido: %s. Solo se permite t2.micro.", [instance_type])
}
