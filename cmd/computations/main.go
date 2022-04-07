package main

import (
	"fmt"

	"github.com/ultravioletrs/cocos/computations"
)

func main() {
	fmt.Println("hello")
	repo := computations.NewRepository()
	c := computations.NewService(repo)
	fmt.Println("hello:", c)
}
