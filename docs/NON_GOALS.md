# Non-goals

- **Not a sandbox.** Mandate does not isolate code execution.
- **Not an observability platform.** It emits receipts; shipping them to a
  SIEM is someone else's job.
- **Not a model.** No LLM is called anywhere in the decision path.
- **Not a payment processor.** It authorises effects; it does not move money.
- **Not a replacement for legal contracts.** A signed grant proves authorisation,
  not legal validity.
- **Not zero-config in production.** A trust root (public keys) and a policy
  must be provisioned deliberately.
