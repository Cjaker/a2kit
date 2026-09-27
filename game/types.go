package game

// Entity identifies something in the world for the session. It can be a player, a mob, or a summon.
// An ID names a spawn slot. A life ends at Death, and the next Spawn of the ID begins another.
type Entity uint32

// Skill is a skill's id from the game files.
type Skill uint32

// NPC is a mob's type id from the game files.
type NPC uint32

// Pos is a position in the zone.
type Pos struct{ X, Y, Z float32 }
