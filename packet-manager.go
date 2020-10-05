package sftp

import (
	"encoding"
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
	incoming  []orderedPacket
	outgoing  []orderedPacket
	writer    io.Writer // connection
	working   *sync.WaitGroup
	counter   uint
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

	go func() {
		for {
			select {
			case pkt := <-s.requests:
				s.incoming = append(s.incoming, pkt)
				sortPackets(s.incoming)
			case pkt := <-s.responses:
				s.outgoing = append(s.outgoing, pkt)
				sortPackets(s.outgoing)
			case <-s.fini:
				return
			}
			s.sendReadyPackets()
		}
	}()

	return s
}

type orderedPacket interface {
	id() uint32
	orderID() uint
}

type orderedRequest struct {
	requestPacket
	orderid uint
}

func (p orderedRequest) orderID() uint { return p.orderid }

type orderedResponse struct {
	responsePacket
	orderid uint
}

func (p orderedResponse) orderID() uint { return p.orderid }

func sortPackets(packets []orderedPacket) {
	sort.Slice(packets, func(i, j int) bool {
		return packets[i].orderID() < packets[j].orderID()
	})
}

func (s *packetManager) newOrderedRequest(p requestPacket) orderedRequest {
	s.counter++
	return orderedRequest{p, s.counter}
}

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
func (s *packetManager) workerChan(
	runWorker func(chan orderedRequest),
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

func (s *packetManager) sendReadyPackets() {
	for len(s.incoming) > 0 && len(s.outgoing) > 0 {
		in := s.incoming[0]
		out := s.outgoing[0]

		if in.orderID() != out.orderID() {
			break
		}

		// This will panic if the out packet type does not implement
		// BinaryMarshaler but that is a bug anyways
		if pkt, err := out.(encoding.BinaryMarshaler).MarshalBinary(); err != nil {
			debug("Error marshaling packet: %v", err)
		} else if _, err = s.writer.Write(pkt); err != nil {
			debug("Error sending packet: %v", err)
		}

		// Shift queues
		copy(s.incoming, s.incoming[1:])            // shift left
		s.incoming[len(s.incoming)-1] = nil         // clear last
		s.incoming = s.incoming[:len(s.incoming)-1] // remove last
		copy(s.outgoing, s.outgoing[1:])            // shift left
		s.outgoing[len(s.outgoing)-1] = nil         // clear last
		s.outgoing = s.outgoing[:len(s.outgoing)-1] // remove last
	}
}
