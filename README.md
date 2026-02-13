# codeforge(WIP)

## goal
simplify the setup of self-hosted cicd setups via a modular approach

## services
- gatekeeper - managing auth for users and services
- overseer - deploying and managing infra such as add on services not part of the core services
- architect - managing terraform state and secrets while encrypting them
- foundary - spin up containers for general cicd tasks via scripts
- worklist - task managment linked to tickets
- vault - git repo and container images wrapper
- shopfront - web gui
