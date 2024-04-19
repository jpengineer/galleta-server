package internal

import (
	"time"
)

var Query = map[string]string{
	"login":                      `SELECT id, first_name, last_name, alias, age, email, password, city, country, country_code, player_status, galleta_status, developer, last_update, created FROM galleta_app.players INNER JOIN galleta_app.countries ON country_name = country WHERE lower(email) = lower($1)`,
	"get_countries":              "SELECT country_code, country_name FROM galleta_app.countries;",
	"get_team":                   `SELECT team.id, team_m.user_id, team.name, team.captain, team.created_by, team.city, team.country, team_m.is_captain, team_m.is_main_team, team.team_status, team.last_update, team.created FROM galleta_app.teams as team INNER JOIN galleta_app.team_members team_m on team_m.team_id = team.id WHERE team_m.user_id = $1;`,
	"get_profile_configurations": `SELECT avatar, avatar_card, type_card, positions FROM galleta_app.player_configurations WHERE player_id = $1;`,
	"get_system_configurations":  `SELECT color_background_menu, color_background_menu_active, color_text_menu, color_background_light, color_background_dark, color_shadow_light, color_shadow_dark, sidebar_slide_left, sidebar_slide_right, slide_menu_effect FROM galleta_app.system_configurations WHERE player_id = $1;`,
	"get_team_members":           `SELECT tm.team_id, tm.user_id, pl.first_name, pl.last_name, pl.alias, pl.player_status, pl.galleta_status, pc.avatar, pc.avatar_card, pc.positions FROM galleta_app.team_members as tm INNER JOIN galleta_app.players pl on pl.id = tm.user_id INNER JOIN galleta_app.player_configurations as pc on pc.player_id = pl.id WHERE tm.team_id = $1 AND tm.user_id <> $2;`,
	"get_player_card":            `SELECT pl.first_name, pl.last_name, pl.age, con.country_code, con.country_name, pc.avatar_card, pc.type_card, pc.positions FROM galleta_app.players as pl INNER JOIN galleta_app.countries as con ON country_name = country INNER JOIN galleta_app.player_configurations as pc ON pl.id = pc.player_id WHERE pl.id = $1;`,
}

type LoginUser struct {
	Name     string `json:"username"`
	Password string `json:"password"`
}

type Country struct {
	Code string `db:"country_code"`
	Name string `db:"country_name"`
}

type Player struct {
	Id            string     `db:"id"`
	FirstName     string     `db:"first_name"`
	LastName      string     `db:"last_name"`
	Alias         string     `db:"alias"`
	Age           int        `db:"age"`
	Email         string     `db:"email"`
	Password      string     `db:"password"`
	City          string     `db:"city"`
	Country       string     `db:"country"`
	CountryCode   string     `db:"country_code"`
	PlayerStatus  bool       `db:"player_status"`
	GalletaStatus bool       `db:"galleta_status"`
	Developer     bool       `db:"developer"`
	LastUpdate    *time.Time `db:"last_update"`
	Created       *time.Time `db:"created"`
}

type PlayerConfiguration struct {
	Avatar     string   `db:"avatar"`
	AvatarCard string   `db:"avatar_card"`
	TypeCard   string   `db:"type_card"`
	Positions  []string `db:"positions"`
}

type SystemConfiguration struct {
	ColorBackgroundMenu       string `db:"color_background_menu"`
	ColorBackgroundMenuActive string `db:"color_background_menu_active"`
	ColorTextMenu             string `db:"color_text_menu"`
	ColorBackgroundLight      string `db:"color_background_light"`
	ColorBackgroundDark       string `db:"color_background_dark"`
	ColorShadowLight          string `db:"color_shadow_light"`
	ColorShadowDark           string `db:"color_shadow_dark"`
	SidebarSlideLeft          bool   `db:"sidebar_slide_left"`
	SidebarSlideRight         bool   `db:"sidebar_slide_right"`
	SlideMenuEffect           bool   `db:"slide_menu_effect"`
}

type TeamMember struct {
	Id         string `db:"id"`
	TeamId     string `db:"team_id"`
	UserId     string `db:"user_id"`
	IsCaptain  bool   `db:"is_captain"`
	IsMainTeam bool   `db:"is_main_team"`
}

type TeamMembers struct {
	TeamId        string   `db:"team_id"`
	UserId        string   `db:"user_id"`
	FirstName     string   `db:"first_name"`
	LastName      string   `db:"last_name"`
	Alias         string   `db:"alias"`
	PlayerStatus  bool     `db:"player_status"`
	GalletaStatus bool     `db:"galleta_status"`
	Avatar        string   `db:"avatar"`
	AvatarCard    string   `db:"avatar_card"`
	Positions     []string `db:"positions"`
}

type Team struct {
	Id         string     `db:"id"`
	UserId     string     `db:"user_id"`
	Name       string     `db:"name"`
	Captain    string     `db:"captain"`
	CreatedBy  string     `db:"created_by"`
	City       string     `db:"city"`
	Country    string     `db:"country"`
	IsCaptain  bool       `db:"is_captain"`
	IsMainTeam bool       `db:"is_main_team"`
	TeamStatus bool       `db:"team_status"`
	LastUpdate *time.Time `db:"last_update"`
	Created    *time.Time `db:"created"`
}

type PlayerCard struct {
	FirstName   string   `db:"first_name"`
	LastName    string   `db:"last_name"`
	Age         int      `db:"age"`
	CountryCode string   `db:"country_code"`
	CountryName string   `db:"country_name"`
	AvatarCard  string   `db:"avatar_card"`
	TypeCard    string   `db:"type_card"`
	Positions   []string `db:"positions"`
}
