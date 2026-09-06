package transport

type WindowClamper struct {
	ClampedSize uint16
	Active      bool
}

func NewWindowClamper(clampedSize uint16) *WindowClamper {
	return &WindowClamper{
		ClampedSize: clampedSize,
		Active:      true,
	}
}

func (w *WindowClamper) ClampWindow(origWin uint16, isHandshake bool) uint16 {
	if !w.Active {
		return origWin
	}
	if isHandshake && origWin > w.ClampedSize {
		return w.ClampedSize
	}
	return origWin
}

func (w *WindowClamper) IsRstLegitimate(rstSeq uint32, lastAckSeq uint32, window uint32) bool {
	diff := rstSeq - lastAckSeq
	maxWin := window
	if maxWin < 4096 {
		maxWin = 4096
	}
	return diff <= maxWin
}
