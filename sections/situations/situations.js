class Situation {
    constuctor(name, notes) {
        this.name;
        this.notes;
    }
}

const bleeding = new Ability('Bleeding', '1 DMG per min. Roll [(Medicine or C) vs DMG] to stop.');
const burning = new Ability('Burning', '1 FDMG per rnd. Roll [Demeanor 6#] to stop, drop, and roll.');
const chase = new Ability('Chase', 'Roll opposed [(Athletics, Acrobatics, Tame, or Drive) + Speed] each rnd. Chase ends when one gets 3 Successes over the other.');
const concealment = new Ability('Concealment', 'You cannot be targeted directly. Blasts are unaffected. Enemies are Defenseless against ATKs from Concealment.');
const cover = new Ability('Cover', 'Material DR reduces DMG.');
const defenseless = new Ability('Defenseless', 'Use Reflex for DEF.');
const falling = new Ability('Falling', '1DMG per 2yds. Roll [Acrobatics # = yds] to halve Falling DMG.');
const friendlyFire = new Ability('Friendly Fire', '-3 RATK at a target next to an ally. Failing requires you to roll [d6 RATK (no modifiers) vs ally’s Reflex].');
const grabbed = new Ability('Grabbed', 'Defenseless. Roll [Acrobatics or Melee vs Grab] to escape.');
const needs = new Ability('Needs', '1 Pain for each deprivation of a Need (see HAZARDS).');
const pain = new Ability('Pain', '-1 per Pain to all rolls and Speed. Pain fades as DMG heals. Some Pain fades based on the source. Unconscious if [Pain > (C + D)].');
const prone = new Ability('Prone', '+1 RATK. +3 Stealth. Speed 1yd.');
const range = new Ability('Range (RNG)', 'RATKs take a -1 penalty per extra RNG. Melee weapons take a penalty against longer Melee weapons = [RNG - enemy RNG].');
const reflex = new Ability('Reflex', '= [Perception]. Default DEF if you are Defenseless or out of AP. Reflex is never rolled. It is a static Difficulty for enemy ATKs.');
const stun = new Ability('Stun', 'Defenseless and cannot take actions. Prone if [Stunned > 1rnd].');
const unarmed = new Ability('Unarmed', 'DMG = [MATK - DEF] up to Melee score. DR is not depleted.');
const unconscious = new Ability('Unconscious', 'Unaware and unable to take actions. 0 DEF.');
const unstable = new Ability('Unstable', '-3 penalty to physical rolls. -3 to RATKs at or from you.');
const visibility = new Ability('Visibility', '-1 to -6 (Blind) to sight-based rolls, including ATK and DEF.');