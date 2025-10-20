package jwt

import (
	"testing"

	"github.com/smarty/gunit"
	"github.com/smarty/gunit/assert/should"
)

func TestAlgorithmSelectionFixture(t *testing.T) {
	gunit.Run(new(AlgorithmSelectionFixture), t)
}

type AlgorithmSelectionFixture struct {
	*gunit.Fixture
}

func (this *AlgorithmSelectionFixture) TestAlgorithmOptions() {
	this.So(translateNamedAlgorithm(noAlgorithm), should.Equal, NoAlgorithm{})
	this.So(translateNamedAlgorithm(hs256), should.Equal, HS256{})
	this.So(translateNamedAlgorithm(hs384), should.Equal, HS384{})
	this.So(translateNamedAlgorithm(hs512), should.Equal, HS512{})
	this.So(func() { translateNamedAlgorithm("Hello") }, should.Panic)
}
