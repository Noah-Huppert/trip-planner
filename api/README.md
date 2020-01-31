# API
Trip planner API.

# Table Of Contents
- [Overview](#overview)
- [Development](#development)
- [Operation](#operation)

# Overview
HTTP REST API.  
Stores data in Postgres.

See [Development](#development) to see how to run code from source.  
See [Operation](#operation) for instructions on how to administer the API, more 
for production use.

# Development
Start Postgres locally:

```
% ./db start
```

Run the API server:

```
% go run .
```

# Operation
The server binary can receive arguments, these tell it to perform administration
actions. If no arguments are received the HTTP API server is run.

Run migrations on the database:

```
% go run . db-migrate
```

Create a user invite code:

```
% go run . create-invite-code
```

This invite code will last for 24 hours.
