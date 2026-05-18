# comserv-app

A simple Go HTTP service for user authentication.

## Requirements

- Go 1.21+

## Running

```bash
go run main.go
```

The server starts on port 8080.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| POST | /login | User login (username + password form fields) |
