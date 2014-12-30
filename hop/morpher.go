package hop

//Handle packet morphing

import (
	"math/rand"
	"time"
)

type HopMorpher interface {
	// return next packet size
	NextPackSize() int
	// TODO: take interarival time into account
	// NextSizeAndInterval() (int, int)
	// Close()
}

// randMopher is the most naive mopher
type randMorpher struct {
	// channel to get next packet size
	token chan int
	mtu   int
}

func newRandMorpher(mtu int) *randMorpher {
	morpher := new(randMorpher)
	morpher.token = make(chan int, 64)
	morpher.mtu = mtu

	go func() {
		t := time.Now().UnixNano()
		r := rand.New(rand.NewSource(t))
		for {
			morpher.token <- r.Intn(morpher.mtu)
		}
	}()

	return morpher
}

func (m *randMorpher) NextPackSize() int {
	return <-m.token
}
