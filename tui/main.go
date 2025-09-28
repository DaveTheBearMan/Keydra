package main

import (
	"log"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/john-marinelli/panes"
	"github.com/charmbracelet/bubbles/key"
)

type TextPane struct {
	textArea textarea.Model
}

func NewTextPane() TextPane {
	ta := textarea.New()
	return TextPane{
		textArea: ta,
	}
}

func (tp TextPane) Init() tea.Cmd {
	return textarea.Blink
}

func (tp TextPane) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		tp.textArea.SetWidth(msg.Width)
		tp.textArea.SetHeight(msg.Height)
		return tp, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return tp, tea.Quit
		}
	}
	var cmd tea.Cmd
	tp.textArea, cmd = tp.textArea.Update(msg)

	return tp, cmd
}

func (tp TextPane) View() string {
	return tp.textArea.View()
}

func (tp TextPane) In() tea.Model {
	tp.textArea.Focus()
	return tp
}

func (tp TextPane) Out() tea.Model {
	tp.textArea.Blur()
	return tp
}

func main() {
	ps := panes.New(
		[][]tea.Model{
			{NewTextPane(), NewTextPane()},
			{NewTextPane(), NewTextPane(), NewTextPane()},
		},
	)

	ps.KeyMap = panes.KeyMap{
		Left:  key.NewBinding(key.WithKeys("ctrl+left")),
		Right: key.NewBinding(key.WithKeys("ctrl+right")),
		Down:  key.NewBinding(key.WithKeys("ctrl+down")),
		Up:    key.NewBinding(key.WithKeys("ctrl+up")),
		Quit:  key.NewBinding(key.WithKeys("ctrl+c")),
	}

	p := tea.NewProgram(ps, tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}