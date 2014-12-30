package hop

import (
	"fmt"
	"testing"
	// "github.com/bigeagle/gohop/logging"
)

type counter struct {
	seq uint32
}

func (c *counter) Seq() uint32 {
	return c.seq
}

type testMopher struct {
	tokens  []int
	counter int
}

func newTestMorpher() *testMopher {
	m := new(testMopher)
	m.tokens = []int{200, 27, 100, 50, 164, 89, 6}
	m.counter = 0
	return m
}

func (m *testMopher) NextPackSize() int {
	t := m.tokens[m.counter]
	m.counter = (m.counter + 1) % len(m.tokens)
	return t
}

func Test_Fragment_1(t *testing.T) {
	// logging.InitLogger(true)
	// logger := logging.GetLogger()

	c := new(counter)
	m := newTestMorpher()
	hf := newHopFragmenter(m)

	frame := make([]byte, 628)
	for i, _ := range frame {
		frame[i] = byte(i % 256)
	}

	packets := hf.Fragmentate(c, frame)
	for i, p := range packets[:len(packets)-1] {
		//fmt.Printf("%v\n\n", p)
		if p.Frag != uint8(i) {
			t.Error("Seg Number Fault")
		}
		if (p.Flag & HOP_FLG_MFR) == 0 {
			t.Error("Flag Fault")
		}
		if p.Dlen != uint16(m.tokens[i%len(m.tokens)]) {
			t.Error("Payload Length Wrong")
		}
	}
	//p := packets[len(packets)-1]
	//fmt.Printf("%v\n\n", p)
	// if p.Flag != HOP_FLG_DAT {
	//     t.Error("Flag Fault")
	// }
	// if p.Dlen != 87 {
	//     t.Error("Payload Length Wrong")
	// }

}

// func Test_Fragment_2(t *testing.T) {
//     // logging.InitLogger(true)
//     // logger := logging.GetLogger()
//
//     c := new(counter)
//     m := newTestMorpher()
//     hf := newHopFragmenter(m)
//
//     frame := make([]byte, 445)
//     for i, _ := range(frame) {
//         frame[i] = byte(i % 256)
//     }
//
//     packets := hf.bufFragmentate(c, frame)
//     for i, p := range(packets[:len(packets)-1]) {
//         if (p.Frag != uint8(i)) {
//             t.Error("Seg Number Fault")
//         }
//         if (p.Flag & HOP_FLG_MFR) == 0 {
//             t.Error("Flag Fault")
//         }
//         if p.Dlen != uint16(m.tokens[i%len(m.tokens)]) {
//             t.Error("Payload Length Wrong")
//         }
//     }
//     p := packets[len(packets)-1]
//     if p.Flag != HOP_FLG_DAT {
//         t.Error("Flag Fault")
//     }
//     if p.Dlen != 68 {
//         t.Error("Payload Length Wrong")
//     }
//     if len(p.noise) != 96 {
//         t.Error("Wrong padding")
//     }
//
// }
//

func Test_Fragment_Assemble(t *testing.T) {
	// logging.InitLogger(true)
	// logger := logging.GetLogger()

	c := new(counter)
	m := newTestMorpher()
	hf := newHopFragmenter(m)

	packets := make([]*HopPacket, 0, 128)
	for i := 0; i < 3; i++ {
		c.seq = uint32(i)
		frame := make([]byte, 564)
		for j, _ := range frame {
			frame[j] = byte(j % 256)
		}
		frags := hf.Fragmentate(c, frame)
		packets = append(packets, frags...)
	}
	//for _, p := range(packets) {
	//    fmt.Println(p.Seq, p.Frag)
	//}

	rpacks := hf.reAssemble(packets)
	for _, p := range rpacks {
		fmt.Println(p)
	}

	// if len(fails) > 0 || len(rpacks) != 3{
	//     t.Error("Error Reassembling")
	// }

	// for _, r := range(rpacks) {
	//     if r.Dlen != 564 || (r.Flag & HOP_FLG_MFR) != 0{
	//         t.Error("Error Reassembling")
	//     }
	// }

	first_packets := packets[:len(packets)-2]
	rpacks = hf.reAssemble(first_packets)
	for _, p := range rpacks {
		fmt.Println(p)
	}

	// if len(fails) != 1 || len(rpacks) != 2{
	//     t.Error("Error Reassembling")
	// }

	// for _, r := range(rpacks) {
	//     if r.Dlen != 564 || (r.Flag & HOP_FLG_MFR) != 0{
	//         t.Error("Error Reassembling")
	//     }
	// }
	// for _, r := range(fails) {
	//     if (r.Flag & HOP_FLG_MFR) == 0 {
	//         t.Error("Error Reassembling")
	//     }
	// }

	second_packets := packets[len(packets)-2:]
	rpacks = hf.reAssemble(second_packets)
	for _, p := range rpacks {
		fmt.Println(p)
	}

	// if len(fails) > 0 || len(rpacks) != 1{
	//     t.Error("Error Reassembling")
	// }

	// for _, r := range(rpacks) {
	//     if r.Dlen != 564 || (r.Flag & HOP_FLG_MFR) != 0{
	//         t.Error("Error Reassembling")
	//     }
	// }

}
