# Build stage
FROM golang:1.26-alpine3.22 AS builder

WORKDIR /app

# Copia primeiro os arquivos de dependência da pasta ionapp para melhor cache
COPY src/go.mod ./
RUN go mod download

# Copia o código fonte da pasta ionapp
COPY src/main.go ./

# Compila com otimizações
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o main .

# Stage final - imagem mínima
FROM alpine:3.23.5

# Instala apenas o necessário e configura usuário não-root
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser

USER appuser
WORKDIR /app

# Copia o binário do stage de build
COPY --from=builder /app/main /app/main

# Expõe a porta 8080
EXPOSE 8080

# Executa a aplicação
CMD ["./main"]
