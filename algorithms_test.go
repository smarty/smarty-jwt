package jwt

import (
	"testing"

	"github.com/smartystreets/assertions/should"
	"github.com/smartystreets/gunit"
)

func TestAlgorithmSelectionFixture(t *testing.T) {
	gunit.Run(new(AlgorithmSelectionFixture), t)
}

type AlgorithmSelectionFixture struct {
	*gunit.Fixture
}

func (this *AlgorithmSelectionFixture) TestAlgorithmOptions() {
	this.So(translateNamedAlgorithm(noAlgorithm), should.Resemble, NoAlgorithm{})
	this.So(translateNamedAlgorithm(hs256), should.Resemble, HS256{})
	this.So(translateNamedAlgorithm(hs384), should.Resemble, HS384{})
	this.So(translateNamedAlgorithm(hs512), should.Resemble, HS512{})
	this.So(func() { translateNamedAlgorithm("Hello") }, should.Panic)
}
