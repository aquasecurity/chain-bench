package printer

import (
	"fmt"

	"github.com/alexeyco/simpletable"
)

func CreateHeader(titles []string) *simpletable.Header {
	header := new(simpletable.Header)
	for _, t := range titles {
		header.Cells = append(header.Cells, headerCell(CellData{text: t}))
	}
	return header
}

func CreateFooter(s Statistics, columnsCount int) *simpletable.Footer {
	footer := new(simpletable.Footer)
	footer.Cells = append(footer.Cells, cell(CellData{span: columnsCount, align: simpletable.AlignLeft, text: fmt.Sprintf("Total Passed Rules: %d out of %d", s.Passed, s.Failed+s.Passed), color: ColorWhite}))
	return footer
}

func CreateBodyRow(cellsData []CellData) []*simpletable.Cell {
	row := []*simpletable.Cell{}
	for _, cd := range cellsData {
		row = append(row, cell(cd))
	}
	return row
}

func cell(data CellData) *simpletable.Cell {
	color := ColorBlue
	if data.color != "" {
		color = data.color
	}
	return &simpletable.Cell{Text: fmt.Sprint(color, data.text), Span: data.span, Align: data.align}
}

func headerCell(data CellData) *simpletable.Cell {
	data.color = ColorGray
	data.align = simpletable.AlignCenter
	return cell(data)
}
