package lib

// Circuit configuration constants
// Configuration: MAX_ROWS=256, MAX_COLS=16, MAX_GROUPS=32, MAX_OPS=4, MAX_HANDLERS=4
// This matches the circom circuit: SimpleVerifier(256, 16, 32, 4, 4)
const (
	MAX_ROWS     = 256
	MAX_COLS     = 16
	MAX_GROUPS   = 32
	MAX_OPS      = 4
	MAX_HANDLERS = 4

	// For 16-ary Merkle tree: 16^3 = 4096 leaves
	// TOTAL_ITEMS = 256 * 16 = 4096, so N_LEVELS = 3
	N_LEVELS = 3

	TOTAL_ITEMS = MAX_COLS * MAX_ROWS // 4096
)

// OpCode constants (fixed - matching circom)
const (
	OP_NOOP       = 0
	OP_MERKLE16   = 1000
	OP_COUNT      = 2000
	OP_SUM_COL    = 2001
	OP_SUM_COL_BY = 3000
)
