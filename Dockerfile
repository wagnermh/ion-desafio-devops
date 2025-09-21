# Usa a versão específica do Golang
FROM golang:1.24.2-alpine

# Define o diretório de trabalho
WORKDIR /app

# Copia os arquivos de dependências primeiro da pasta ionapp
COPY ionapp/go.mod ./
RUN go mod download

# Copia o código fonte da pasta ionapp
COPY ionapp/main.go ./

# Compila a aplicação
RUN go build -o main .

# Expõe a porta 8080
EXPOSE 8080

# Executa a aplicação
CMD ["./main"]
