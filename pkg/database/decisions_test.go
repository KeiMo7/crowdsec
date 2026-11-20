package database

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func TestLatestDecisionID(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	latest, err := c.LatestDecisionID(ctx)
	require.NoError(t, err)
	require.Zero(t, latest, "empty table has no cursor")

	var lastID int

	for range 3 {
		d, err := c.Ent.Decision.Create().
			SetUntil(time.Now().UTC().Add(time.Hour)).
			SetScenario("test").
			SetType("ban").
			SetScope("Ip").
			SetValue("1.2.3.4").
			SetOrigin("test").
			Save(ctx)
		require.NoError(t, err)

		lastID = d.ID
	}

	latest, err = c.LatestDecisionID(ctx)
	require.NoError(t, err)
	require.Equal(t, lastID, latest)

	// deleting the newest rows rewinds the cursor, but ids are never reused
	_, err = c.Ent.Decision.Delete().Exec(ctx)
	require.NoError(t, err)

	latest, err = c.LatestDecisionID(ctx)
	require.NoError(t, err)
	require.Zero(t, latest)

	d, err := c.Ent.Decision.Create().
		SetUntil(time.Now().UTC().Add(time.Hour)).
		SetScenario("test").
		SetType("ban").
		SetScope("Ip").
		SetValue("1.2.3.5").
		SetOrigin("test").
		Save(ctx)
	require.NoError(t, err)
	require.Greater(t, d.ID, lastID, "decision ids must keep climbing across deletes")
}

func TestExpireDecisionsForRule(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	create := func(scenario, version, hash, value string) *ent.Decision {
		alert, err := c.Ent.Alert.Create().
			SetScenario(scenario).
			SetScenarioVersion(version).
			SetScenarioHash(hash).
			Save(ctx)
		require.NoError(t, err)

		decision, err := c.Ent.Decision.Create().
			SetUntil(time.Now().UTC().Add(time.Hour)).
			SetScenario(scenario).
			SetType("ban").
			SetScope("Ip").
			SetValue(value).
			SetOrigin("crowdsec").
			SetOwner(alert).
			Save(ctx)
		require.NoError(t, err)
		return decision
	}

	target := create("test/http-404", "0.3", "hash-new", "192.0.2.1")
	oldVersion := create("test/http-404", "0.2", "hash-old", "192.0.2.2")
	otherScenario := create("test/ssh", "0.3", "hash-new", "192.0.2.3")

	count, expired, err := c.ExpireDecisionsForRule(ctx, "test/http-404", "0.3", "hash-new")
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Len(t, expired, 1)
	require.Equal(t, target.ID, expired[0].ID)

	target, err = c.Ent.Decision.Get(ctx, target.ID)
	require.NoError(t, err)
	require.False(t, target.Until.After(time.Now().UTC()))

	oldVersion, err = c.Ent.Decision.Get(ctx, oldVersion.ID)
	require.NoError(t, err)
	require.True(t, oldVersion.Until.After(time.Now().UTC()))

	otherScenario, err = c.Ent.Decision.Get(ctx, otherScenario.ID)
	require.NoError(t, err)
	require.True(t, otherScenario.Until.After(time.Now().UTC()))
}

func TestExpireDecisionsWithScenarioVersionFilter(t *testing.T) {
	ctx := t.Context()
	c := getDBClient(t, ctx)

	create := func(version string) *ent.Decision {
		alert, err := c.Ent.Alert.Create().
			SetScenario("test/http-404").
			SetScenarioVersion(version).
			SetScenarioHash("hash-" + version).
			Save(ctx)
		require.NoError(t, err)

		decision, err := c.Ent.Decision.Create().
			SetUntil(time.Now().UTC().Add(time.Hour)).
			SetScenario("test/http-404").
			SetType("ban").
			SetScope("Ip").
			SetValue("192.0.2." + version[len(version)-1:]).
			SetOrigin("crowdsec").
			SetOwner(alert).
			Save(ctx)
		require.NoError(t, err)
		return decision
	}

	target := create("v1")
	other := create("v2")

	count, expired, err := c.ExpireDecisionsWithFilter(ctx, map[string][]string{
		"scenario":         {"test/http-404"},
		"scenario_version": {"v1"},
	})
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, target.ID, expired[0].ID)

	other, err = c.Ent.Decision.Get(ctx, other.ID)
	require.NoError(t, err)
	require.True(t, other.Until.After(time.Now().UTC()))
}
