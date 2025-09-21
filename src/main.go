package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Desafio técnico DevOps!")
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server is running at port 8080")
	http.ListenAndServe(":8080", nil)
}
