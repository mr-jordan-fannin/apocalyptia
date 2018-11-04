// BASICS
const basics = {
    "Character": "",
    "Game Narrator": "",
    "Round": "",
    "Team": "",
    "Turn": ""
}

// DICE
const dice = {
    "Botch": "If you roll 1 on a die, re-roll to check for a Botch. If a 1 is rolled again, you Botch, meaning you fail very badly. For any other number, your d6 roll is just a 1. Bonus rolls from Exploding dice do not Botch.<br>The GN is given a great deal of lattitude to be creative when determining the effects of Botching under various circumstances, but they should always be fair. Whenever a Character Botches, they get +1 Experience Point because we learn the most from our greatest failures.<br><table><tr><td>3#</td><td>Simple</td><td>6#</td><td>Typical</td><td>9#</td><td>Hard</td><td>12#</td><td>Extreme</td></tr></table>",
    "d6": "When you want to attempt a difficult action, roll one six-sided die (“d6”) to decide a fair outcome. Added to the d6 roll is the Character’s score in a Trait, Instinct, or Skill, depending on the action. Finally, add or subtract from the roll any modifiers relevant to the circumstances, as determined by the Game Narrator (GN). The formula for a roll is always shown in [brackets].",
    "Difficulty": "The Result of your roll be greater than or equal to the Difficulty number to be successful. Difficulties are indicated by the # symbol. The GN or an opposing roll set the # for your rolls.",
    "Explode": "If a 6 is rolled, re-roll it again and again as long as 6's continue. Add all of these d6 rolls together, then calculate your Result.",
    "Fail": "If [Result &lt#], the attempted action did not work.",
    "Result": "[d6 roll + Score &#177; Modifiers]",
    "Rote Actions": "If your [(Score + Modifiers) &gt= #] before the d6 roll, and you can take your time, you Succeed automatically.",
    "Rounding": "When a rule involves a fraction, always round down.",
    "Success": "If [Result &gt= #], the attempted action worked. Re-roll ties on opposed rolls. The degree of Success is important for some rolls.",
    "Table Rolling": "Number column headers (d6, d66, d666) indicate that you must roll one, two, or three d6s (one per number column) to get a random row.",
    "Teamwork": "If Characters want to help each other perform a task, they all roll at once but only the best roll is used, unless someone Botches (see below) in which case the Botch is used."
}


// TRAITS
const traits = {
    desc: "The four Traits range from 1 to 6. You get 12 points for Traits. Trait rolls are [d6 + Trait]. Trait scores set the upper limit for their Skills. The average person would have a 3 in each Trait.",
    "Trait Flow": "Once per year (in-game), you may choose to move 1 point from one Trait to another for 24XP. Traits can only be changed by ±1 in this way. Recalculate any associated Instincts and Properties.",
    "Agility": "",
    "Brains": "",
    "Constitution": "",
    "Demeanor": "",
}


// INSTINCTS
const instincts = {
    desc: "Instincts are derived from their parent Trait.",
    "Athletics": {
        formula: "[C]",
        desc: "Climb at [Speed / 2]. Swim at [Speed / 4]."
    },
    "Perception": {
        formula: "[B]",
        desc: "This is rapidly processing you sensory input. Spend 1AP to roll Perception to search, vs Stealth to detect a Concealed enemy, vs Survival to track, or vs Socialize or Perform to discern intentions. When not rolling, your Perception score sets the # for enemy Stealth or any other roll opposed by Perception."
    },
    "Socialize": {
        formula: "[D]",
        desc: "This is how good you are at getting others to like you."
    },
    "Stealth": {
        formula: "[A]",
        desc: "This is your talent for remaining undetected. +3 Stealth when Prone. +3 Stealth if you do not move. Spend 1AP and roll [Stealth vs Perception] to attempt to Conceal yourself. Make only one Move each rnd to remain Concealed. When not rolling, your Stealth score sets the # for enemy Perception rolls. Targets are Defenseless against Concealed ATKs."
    }
}


// SKILLS
const skills = {
    desc: "",
    "Skill Flow": "",
    "Specialty": "",
    "Acrobatics": {
        desc: "",
        "Dodge": "",
        "Jump": ""
    },
    "Build": {
        desc: "",
        "Customize": "",
        "Repair: ""
    },
    "Drive": {
        desc: "",
        "Ram": "",
        "Stunt": ""
    },
    "Larceny": {
        desc: "",
        "Disable": "",
        "Steal": ""
    }
leadership
    encourage
    order
medicine
    first-aid
    surgery
melee
    block
    strike
perform
    deceive
    distract
ranged
    shoot
    throw
science
    chemistry
    technology
survival
    forage
    navigate
tame
    command
    train


// PROPERTIES
const properties = {
    "description": "Properties derive their scores from Traits, Instincts, or Skills.",
    "Actions": "[(A + B) / 2] Taking an action costs a number of Action Points, usually only 1AP. AP refills at the beginning of your next turn.",
    "Comrades": "These are close allies for whom you would risk much to protect. List your Comrades in order of importance to you if you want to track the priority of your relationships in your Team.",
    "Experience": "[B per session] XP is earned once per game session. The GN may give bonus XP. Spend XP to buy Abilities.",
    "Health": "[C x 3] This is the amount of DMG you can take. You fall Prone and start Bleeding at [HP / 2] and remain so until healed. Go Unconscious at 0 HP and die at [-C] HP. HP is recovered by 1 per day of rest with a [C vs DMG] roll.",
    "Luck": "[D] Luck rolls [d6 + current Luck points] are made to determine your fate in matters of pure chance. Luck points refill at dawn each day. You may spend Luck in dramatic moments to:<ul><li>Take a re-roll with a +6 bonus.</li><li>Get +1AP.</li><li>Give a Luck point to a Comrade.</li></ul>",
    "Psyche": "<p>= [D] This is a rough measure of your mental health on a sliding scale from Crazy to Sane. Fill in the dot = [your Demeanor] counting from Crazy. Especially relaxing or inspiring things might move the dot one step towards Sane. Extremely traumatic things move the dot one step towards Crazy.</p><p>During the game session, Players and the GN should make a note when something happens that might alter the Character’s Psyche. After the game session, they should discuss the events that occurred and whether they were personally relevant enough to constitute a change in Psyche for that Character at that time.</p><p>Upon losing your last dot of Psyche, the GN takes control of your Character for d6hrs of in-game time. The GN can decide whether or not you remember what happens during this period. Afterward, the Character starts back at 1 Psyche. Lose 1 Psyche when a Comrade dies.</p>",
    "Speed": "[A + C] Spend 1AP to move [Speed] yds. Spend 2AP per rnd to Run [Speed x 2] for up to [C x 5] mins. March at [Speed / 2] mph for up to [C x 2] hrs.",
}


// ABILITY
const abilities = {
    "Ambidextrous": {
        desc: "+1 Socialize for First Impressions.",
        max: "3",
        xp: "3"
    },
    "Assassin": {
        desc: "+3 DMG from Concealment.",
        max: "1",
        xp: "18"
    },
    "Charismatic": {
        desc: "+1 Socialize for First Impressions.",
        max: "3",
        xp: "3"
    },
    "Danger Sense": {
        desc: "+1 Reflex.",
        max: "1",
        xp: "9"
    },
    "Discipline": {
        desc: "Ignore 1 Pain penalty.",
        max: "3",
        xp: "6"
    },
    "Efficient Work": {
        desc: "[Time / 2] for a Skill (minimum 1 action).",
        max: "1",
        xp: "6"
    },
    "Fast Draw": {
        desc: "Free weapon draw once per rnd.",
        max: "1",
        xp: "6"
    },
    "Favorite Weapon": {
        desc: "Botch is only a Fail with this one weapon.",
        max: "1",
        xp: "3"
    },
    "Fencing": {
        desc: "Free Block roll once per rnd.",
        max: "1",
        xp: "12"
    },
    "Firm Grip": {
        desc: "Use 2h weapons in 1h, up to Size = [C].",
        max: "1",
        xp: "15"
    },
    "Fleet Footed": {
        desc: "+1 Speed.",
        max: "3",
        xp: "6"
    },
    "Fortunate": {
        desc: "+1 Luck.",
        max: "1",
        xp: "9"
    },
    "Freerunning": {
        desc: "Climb at [Speed] for 2AP.",
        max: "1",
        xp: "9"
    },
    "Hard Headed": {
        desc: "Ignore Stun from Head DMG.",
        max: "1",
        xp: "15"
    },
    "Hone Instinct": {
        desc: "+1 to a specific Instinct.",
        max: "1",
        xp: "9"
    },
    "Hyper Immunity": {
        desc: "+1 C to resist Diseases and Drug effects.",
        max: "3",
        xp: "3"
    },
    "Martial Arts": {
        desc: "Free Grab roll once per rnd.",
        max: "1",
        xp: "12"
    },
    "Multilingual": {
        desc: "Learn a different form of communication.",
        max: "9",
        xp: "9"
    },
    "Pack Mentality": {
        desc: "+1 ATK at same target a Comrade ATKs.",
        max: "1",
        xp: "3"
    },
    "Powerful Strike": {
        desc: "+1 DMG for a specific Melee weapon.",
        max: "1",
        xp: "15"
    },
    "Quick Reload": {
        desc: "Free Reload once per rnd.",
        max: "1",
        xp: "6"
    },
    "Second Chance": {
        desc: "Spend this Ability to avoid Death once.",
        max: "9",
        xp: "30"
    },
    "Self Improvement": {
        desc: "+1 to a Trait (max 6).",
        max: "3",
        xp: "30"
    },
    "Side-step": {
        desc: "Free Dodge roll once per rnd.",
        max: "1",
        xp: "12"
    },
    "Specialize": {
        desc: "+1 to a specific Skill Specialty.",
        max: "1",
        xp: "3"
    },
    "Tough": {
        desc: "+1 HP.",
        max: "3",
        xp: "24"
    },
    "Unorthodox": {
        desc: "Pick a new parent Trait for a specific Skill.",
        max: "1",
        xp: "9"
    },
    "Vehicle Operation": {
        desc: "Proficiently operate a complex vehicle.",
        max: "1",
        xp: "18"
    },
    "Vendetta": {
        desc: "+1 ATK against members of one Faction.",
        max: "1",
        xp: "3"
    },
    "Weapon Training": {
        desc: "+1 ATK for a specific weapon.",
        max: "1",
        xp: "6"
    }
}


// COMBAT
attack
    matk
    ratk
damage
    recovery
    death
defense
    reflex
movement
vehicle combat
    conditions
    occupants
    pedestrians
    tires
    wreck


// MANEUVER
const maneuvers = {
    desc: "",
    "Aim": "Hold your weapon on target and spend 1AP each rnd for +1 ATK, up to 3AP over 3 or more rnds to get +3 ATK. Defenseless while Aiming.",
    "Called Shot": "ATK targeting the Head or Limbs. Head ATKs are at -3, do [DMG x 2], and Stun for 1rnd. Limb ATKs are at -1, do [DMG / 2], and cause the enemy to drop a held item (Arms) or be knocked Prone (Legs).",
    "Disarm": "Roll [MATK vs Melee (+[C] if the weapon is used two-handed)]. The weapon flies d6yds. Attacker gets the weapon if they are Unarmed.",
    "Dual-Wield": "Once per rnd, you may roll ATK or Block for both weapons at a penalty [-1 Primary, -3 Off-hand] for 1AP. Take the best weapon roll.",
    "Duck": "Drop Prone and/or move 1yd behind Cover when you Dodge. Material’s DR reduces DMG.",
    "Grab": "0DMG MATK to render an enemy Defenseless. Spend 1AP per rnd to retain Grab. Roll [(Acrobatics or Melee) vs Grab] to escape.<ul><li>Attack: Make an ATK against a Grabbed enemy.</li><li>Hold: Block ATKs with Grabbed enemy as a Shield.</li><li>Toss: Throw Grabbed enemy [C] yds, leaving them Prone.</li></ul>",
    "Hide": "Roll [Stealth vs Perception] to gain Concealment.",
    "Interrogate": "Roll [Socialize vs D] to get information out of a subject who does not want to help, but without resorting to violence. Each roll takes d6mins of conversation.<br>If the interrogator Succeeds, the subject gives up a fact (wittingly or unwittingly). If the subject Succeeds, they become hardened against further questioning, imposing a -1 penalty on subsequent attempts. After Fails = [D], the interrogator gives up or the subject cracks and tells everything they know.",
    "Negotiate": "If opposed parties are willing to talk out their differences, each side start with a list of negotiable desires.<br>Roll [Socialize vs Socialize] once per desire. Attitude and situational modifiers should be applied by the GN. Success means you get your desire and the opposed negotiator concedes. Either side can choose to concede a desire without rolling.<br>If one side accumulates more than double the concessions of the other, the losing negotiator will feel cheated and end the negotiations. Some desires may be non-negotiable.",
    "Protect": "Become the new target of an ATK targeting someone within 1yd of you. You may still Block as normal, but you cannot Dodge the ATK.",
    "Recruit": "Roll [Leadership vs D] to convince someone to join your side. If they are someone’s follower, roll [Leadership vs Leadership]. Attitude and situational modifiers should be applied by the GN.",
    "Reload": "Replace ammunition in a Ranged weapon. Some weapons require multiple Actions to Reload.",
    "Shove": "Roll [MATK vs C] to push an enemy [C] yds away. 0DMG.",
    "Taunt": "Roll [Leadership vs D]. Provoke the enemy into exclusively attacking you. The degree of Success is a penalty to the loser’s next roll. The enemy is Stunned for 1rnd if [penalty > enemy’s D].",
    "Torture": "Roll [Medicine vs prisoner’s C] once per hour to cause a prisoner d6 Pain to soften the prisoner’s resolve without killing them. Failure does d6 DMG to the prisoner. Roll [D vs D] at the end of each hour (Pain penalty applies). Failure causes -1 Psyche loss. At 0 Psyche, either the torturer cannot do it anymore and gives up, or the prisoner is broken and can be controlled with Leadership or Tame until freed.",
    "Trip": "Roll [MATK vs A] to knock an enemy Prone. 0DMG.",
}


// SITUATION
const situations = {
    desc: "",
    "Bleeding": "1 DMG per min. Roll [(Medicine or C) vs DMG] to stop.",
    "Burning": "1 FDMG per rnd. Roll [Demeanor 6#] to stop, drop, and roll.",
    "Chase": "Roll opposed [(Athletics, Acrobatics, Tame, or Drive) + Speed] each rnd. Chase ends when one gets 3 Successes over the other.",
    "Concealment": "You cannot be targeted directly. Blasts are unaffected. Enemies are Defenseless against ATKs from Concealment.",
    "Cover": "Material DR reduces DMG.",
    "Defenseless": "Use Reflex for DEF.",
    "Dehydration": "",
    "Exhaustion": "",
    "Falling": "1DMG per 2yds. Roll [Acrobatics # = yds] to halve Falling DMG.",
    "Friendly Fire": "-3 RATK at a target next to an ally. Failing requires you to roll [d6 RATK (no modifiers) vs ally’s Reflex].",
    "Grabbed": "Defenseless. Roll [Acrobatics or Melee vs Grab] to escape.",
    "Hypothermia": "",
    "Pain": "-1 per Pain to all rolls and Speed. Pain fades as DMG heals. Some Pain fades based on the source. Unconscious if [Pain &gt (C + D)].",
    "Prone": "+1 RATK. +3 Stealth. Speed 1yd.",
    "Radiation": "",
    "Range": "RATKs take a -1 penalty per extra RNG. Melee weapons take a penalty against longer Melee weapons = [RNG - enemy RNG].",
    "Starvation": "",
    "Stunned": "Defenseless and cannot take actions. Prone if [Stunned &gt 1rnd].",
    "Suffocation": "",
    "Unarmed": "DMG = [MATK - DEF] up to Melee score. DR is not depleted.",
    "Unconscious": "Unaware and unable to take actions. 0 DEF.",
    "Unstable": "-3 penalty to physical rolls. -3 to RATKs at or from you.",
    "Visibility": "-1 to -6 (Blind) to sight-based rolls, including ATK and DEF.",
}


// GEAR
gear
    size

armor attributes
    damage reduction
    camo
    cold-resistance
    fire-resistance

weapon attributes
    1-handed
    2-handed
    auto
    blast
    fdmg
    pierce
    chop
    sawn-off

armor
    athletic pads
    ghillie suit
    kevlar vest
    nbc suit
    riot armor
    thick clothing

melee weapons
    ax
    baseball bat
    brass knuckles
    crowbar
    hammer
    hatchet
    knife
    machete
    shield
    sledgehammer
    spear
    staff

ranged weapons
    assault rifle
    battle rifle
    combat pistol
    compound bow
    crossbow
    double-barrel shotgun
    hunting rifle
    pump shotgun
    revolver
    submachine gun
    target pistol
    target rifle

special ammo
    armor piercing
    broadhead arrow
    buckshot
    hollow point
    match
    slug

bombs
    flashbang
    frag
    molotov
    smoke
    teargas
    thermite

drugs
    alcohol
    antibiotic
    hallucinogen
    painkiller
    sedative
    stimulant

medical
    bandage
    crutch
    surgery kit

vehicles
    cargo
    fuel
    handling
    mpg
    motorcycle
    pickup
    sedan
    semi-truck
    suv
    wagon


// ENVIRONMENT
biome
    desert
    forest
    mountain
    plains
    swamp
    tundra

weather
    blizzard
    dust storm
    fog
    heatwave
    thunderstorm
    wildfire

material
    brick
    concrete
    drywall
    glass
    hardwood
    plywood
    sheet metal
    steel

traps
    deadfall
    pendulum
    pit
    snare
    spring gun
    stakes


// EXTRAS
extra
    dog
    horse