package sftp

import (
	"encoding"
	"fmt"
	"io"
	"sort"
	"sync"
)

const sftpServerWorkerCount = 8

// packetManager ensures outgoing packets are in the same order as the incoming
// per section 7 of the RFC.
type packetManager struct {
	requests  chan orderedPacket
	responses chan orderedPacket
	fini      chan struct{}
	incoming  orderedPackets
	outgoing  orderedPackets
	writer    io.Writer // connection
	working   *sync.WaitGroup
	counter   uint32
}

type packetSender interface {
	sendPacket(encoding.BinaryMarshaler) error
}

func newPktMgr(writer io.Writer) *packetManager {
	s := &packetManager{
		requests:  make(chan orderedPacket, sftpServerWorkerCount),
		responses: make(chan orderedPacket, sftpServerWorkerCount),
		fini:      make(chan struct{}),
		incoming:  make([]orderedPacket, 0, sftpServerWorkerCount),
		outgoing:  make([]orderedPacket, 0, sftpServerWorkerCount),
		writer:    writer,
		working:   &sync.WaitGroup{},
	}
	go s.controller()
	return s
}

//// packet ordering
func (s *packetManager) newOrderID() uint32 {
	s.counter++
	return s.counter
}

type orderedRequest struct {
	requestPacket
	orderid uint32
}

func (s *packetManager) newOrderedRequest(p requestPacket) orderedRequest {
	return orderedRequest{requestPacket: p, orderid: s.newOrderID()}
}
func (p orderedRequest) orderID() uint32       { return p.orderid }
func (p orderedRequest) setOrderID(oid uint32) { p.orderid = oid }

type orderedResponse struct {
	responsePacket
	orderid uint32
}

func (p orderedResponse) orderID() uint32       { return p.orderid }
func (p orderedResponse) setOrderID(oid uint32) { p.orderid = oid }

type orderedPacket interface {
	id() uint32
	orderID() uint32
}
type orderedPackets []orderedPacket

func (o orderedPackets) Sort() {
	sort.Slice(o, func(i, j int) bool {
		return o[i].orderID() < o[j].orderID()
	})
}

//// packet registry
// register incoming packets to be handled
func (s *packetManager) incomingPacket(pkt orderedRequest) {
	s.working.Add(1)
	s.requests <- pkt
}

// register outgoing packets as being ready
func (s *packetManager) readyPacket(pkt orderedResponse) {
	s.responses <- pkt
	s.working.Done()
}

// shut down packetManager controller
func (s *packetManager) close() {
	// pause until current packets are processed
	s.working.Wait()
	close(s.fini)
}

// Passed a worker function, returns a channel for incoming packets.
// Keep process packet responses in the order they are received while
// maximizing throughput of file transfers.
func (s *packetManager) workerChan(runWorker func(chan orderedRequest),
) chan orderedRequest {

	// multiple workers for faster read/writes
	rwChan := make(chan orderedRequest, sftpServerWorkerCount)
	for i := 0; i < sftpServerWorkerCount; i++ {
		runWorker(rwChan)
	}

	// single worker to enforce sequential processing of everything else
	cmdChan := make(chan orderedRequest)
	runWorker(cmdChan)

	pktChan := make(chan orderedRequest, sftpServerWorkerCount)
	go func() {
		for pkt := range pktChan {
			switch pkt.requestPacket.(type) {
			case *fxpReadPkt, *fxpWritePkt:
				s.incomingPacket(pkt)
				rwChan <- pkt
				continue
			case *fxpClosePkt:
				// wait for reads/writes to finish when file is closed
				// incomingPacket() call must occur after this
				s.working.Wait()
			}
			s.incomingPacket(pkt)
			// all non-RW use sequential cmdChan
			cmdChan <- pkt
		}
		close(rwChan)
		close(cmdChan)
		s.close()
	}()

	return pktChan
}

// process packets
func (s *packetManager) controller() {
	for {
		select {
		case pkt := <-s.requests:
			s.incoming = append(s.incoming, pkt)
			s.incoming.Sort()
		case pkt := <-s.responses:
			s.outgoing = append(s.outgoing, pkt)
			s.outgoing.Sort()
		case <-s.fini:
			return
		}
		s.maybeSendPackets()
	}
}

// send as many packets as are ready
func (s *packetManager) maybeSendPackets() {
	for {
		if len(s.outgoing) == 0 || len(s.incoming) == 0 {
			break
		}
		out := s.outgoing[0]
		in := s.incoming[0]
		if in.orderID() == out.orderID() {
			if marshaler, ok := out.(encoding.BinaryMarshaler); ok {
				if pkt, err := marshaler.MarshalBinary(); err != nil {
					debug("Error marshaling packet: %v", err)
				} else if _, err = s.writer.Write(pkt); err != nil {
					debug("Error sending packet: %v", err)
				}
			} else {
				msg := fmt.Sprintf("cannot send packet (not encoding.BinaryMarshaler): %+v", out)
				panic(msg)
			}
			// pop off heads
			copy(s.incoming, s.incoming[1:])            // shift left
			s.incoming[len(s.incoming)-1] = nil         // clear last
			s.incoming = s.incoming[:len(s.incoming)-1] // remove last
			copy(s.outgoing, s.outgoing[1:])            // shift left
			s.outgoing[len(s.outgoing)-1] = nil         // clear last
			s.outgoing = s.outgoing[:len(s.outgoing)-1] // remove last
		} else {
			break
		}
	}
}
