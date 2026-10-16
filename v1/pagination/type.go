package pagination

type Pagination struct {
	Offset    int     `json:"-"`
	TotalPage int     `json:"-"`
	TotalData int     `json:"-"`
	Cursor    *Cursor `json:"-"`

	CursorEncoded string `json:"cursor" form:"cursor"`
	Limit         int    `json:"limit" form:"limit"`
	Page          int    `json:"page" form:"page"`
}

type PaginationResult struct {
	// Cursor based
	NextCursor string `json:"next_cursor,omitempty"`
	SelfCursor string `json:"self_cursor,omitempty"`
	PrevCursor string `json:"prev_cursor,omitempty"`

	// Offset based
	Limit int  `json:"limit,omitempty"`
	Page  *int `json:"page,omitempty"`
}
