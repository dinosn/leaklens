package matcher

import "github.com/dlclark/regexp2"

func regexp2ByteSpan(content string, match *regexp2.Match) (int, int) {
	if match == nil {
		return 0, 0
	}
	return runeIndexLengthToByteSpan(content, match.Index, match.Length)
}

func runeIndexLengthToByteSpan(content string, runeStart, runeLen int) (int, int) {
	if runeStart < 0 {
		runeStart = 0
	}
	if runeLen < 0 {
		runeLen = 0
	}
	runeEnd := runeStart + runeLen
	if runeEnd < runeStart {
		runeEnd = runeStart
	}

	start, end := -1, -1
	runePos := 0
	for bytePos := range content {
		if runePos == runeStart && start == -1 {
			start = bytePos
		}
		if runePos == runeEnd {
			end = bytePos
			break
		}
		runePos++
	}

	if start == -1 {
		if runeStart >= runePos {
			start = len(content)
		} else {
			start = 0
		}
	}
	if end == -1 {
		if runeEnd >= runePos {
			end = len(content)
		} else {
			end = start
		}
	}
	if end < start {
		end = start
	}
	return start, end
}
