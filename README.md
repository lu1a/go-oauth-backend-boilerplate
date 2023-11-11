# tRPC-esque API with OAUTH

My aim with this is to emulate the handiness of AuthJS + tRPC without needing React.
So, this can be the backend component for a separately-hosted frontend somewhere. (Framework/language agnostic!)

The file layout will hopefully be familiar to devs who have touched tRPC.

There will be:
```
/[root]
│   README.md
│   main.go
│   ...
│
└───/api
│   │   index.go
│   └───routers
│       └───/account
│           │   index.go
│           │   types.go
│           │   test.go
│           │   ...
│       └───/organisation
│           │   index.go
│           │   types.go
│           │   test.go
│           │   ...
│       └───/project
│           │   index.go
│           │   types.go
│           │   test.go
│           │   ...
│       ...
```

The `types.go` file in each sub-folder can be compiled into TypeScript for whatever frontend is using it,
with some formatting to show what request inside the /api/account/... responds with a given struct.

Needless to say this won't strictly follow REST or CRUD. A request will either be a `query` or a `mutation`.