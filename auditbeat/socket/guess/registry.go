package guess

import "fmt"

// GuesserFactory is a factory function for guesses.
type GuesserFactory func() Guesser

// Register stores the registered guesses.
type Register struct {
	factories map[string]GuesserFactory
}

// Registry serves as a registration point for guesses.
var Registry = Register{
	factories: make(map[string]GuesserFactory),
}

// AddGuess registers a new guess.
func (r *Register) AddGuess(factory GuesserFactory) error {
	guess := factory()
	if _, found := r.factories[guess.Name()]; found {
		return fmt.Errorf("guess %s is duplicated", guess.Name())
	}
	r.factories[guess.Name()] = factory
	return nil
}

// GetList returns a list of registered guesses.
func (r *Register) GetList() (list []Guesser) {
	for _, factory := range r.factories {
		list = append(list, factory())
	}
	return list
}
