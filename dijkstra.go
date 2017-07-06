package main

import (
	"github.com/RyanCarrier/dijkstra"
)

type Dijkstra interface {
	AddNode(name string, links map[string]int)
	Path(a, b string) ([]string, error)
}

type dijkstraGraph struct {
	*dijkstra.Graph
	namesToIndex map[string]int
	indexToNames []string
}

func NewDijkstra() Dijkstra {
	return &dijkstraGraph{dijkstra.NewGraph(), map[string]int{}, nil}
}

func (d *dijkstraGraph) vertex(name string) int {
	i, ok := d.namesToIndex[name]
	if !ok {
		i = len(d.indexToNames)
		d.namesToIndex[name] = i
		d.indexToNames = append(d.indexToNames, name)
		d.AddVertex(i)
	}
	return i
}

func (d *dijkstraGraph) AddNode(name string, links map[string]int) {
	i := d.vertex(name)
	for dest, weight := range links {
		di := d.vertex(dest)
		d.AddArc(i, di, int64(weight))
	}
}

func (d *dijkstraGraph) Path(src, dest string) ([]string, error) {
	var res []string
	path, err := d.Shortest(d.vertex(src), d.vertex(dest))
	if err != nil {
		return nil, err
	}
	for _, v := range path.Path {
		res = append(res, d.indexToNames[v])
	}
	return res, nil
}
