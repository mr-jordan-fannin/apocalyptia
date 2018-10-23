class Ability {
    constructor(name, notes, max, xp) {
        this.name = name;
        this.notes = notes;
        this.max = max;
        this.xp = xp;
    }
}

const charismatic = new Ability('Charismatic', '+1 Socialize for First Impressions.', 3, 3);
const favoriteWeapon = new Ability('Favorite Weapon', 'Botch is only a Fail with this one weapon', 1, 3);
const hyperImmunity = new Ability('Hyper Immunity', '+1 C to resist Diseases and Drug effects.', 3, 3);
const packMentality = new Ability('Pack Mentality', '+1 ATK at same target a Comrade ATKs.', 1, 3);
const specialize = new Ability('Specialize*', '+1 to a specific Skill Specialty.', 1, 3);
const vendetta = new Ability('Vendetta', '+1 ATK against members of one Faction.', 1, 3);

const discipline = new Ability('Discipline', 'Ignore 1 Pain penalty.', 3, 6);
const efficientWork = new Ability('Efficient Work*', '[Time / 2] for a Skill (minimum 1 action).', 1, 6);
const fastDraw = new Ability('Fast Draw', 'Free weapon draw once per rnd.', 1, 6);
const fleetFooted = new Ability('Fleet Footed', '+1 Speed.', 3, 6);
const quickReload = new Ability('Quick Reload', 'Free Reload once per rnd.', 1, 6);
const weaponTraining = new Ability('Weapon Training*', '+1 ATK for a specific weapon.', 1, 6);

const dangerSense = new Ability('Danger Sense', '+1 Reflex.', 1, 9);
const fortunate = new Ability('Fortunate', '+1 Luck.', 1, 9);
const freeRunning = new Ability('Free Running', 'Climb at [Speed] for 2AP.', 1, 9);
const honeInstinct = new Ability('Hone Instinct*', '+1 to a specific Instinct.', 1, 9);
const multilingual = new Ability('Multilingual*', 'Learn a different form of communication.', 9, 9);
const unorthodox = new Ability('Unorthodox*', 'Pick a new parent Trait for a specific Skill.', 1, 9);

const fencing = new Ability('Fencing', 'Free Block roll once per rnd.', 1, 12);
const martialArts = new Ability('Martial Arts', 'Free Grab roll once per rnd.', 1, 12);
const sideStep = new Ability('Side-step', 'Free Dodge roll once per rnd.', 1, 12);

const firmGrip = new Ability('Firm Grip', 'Use 2h weapons in 1h, up to Size = [C].', 1, 15);
const hardHeaded = new Ability('Hard Headed', 'Ignore Stun from Head DMG.', 1, 15);
const powerfulStrike = new Ability('Powerful Strike*', '+1 DMG for a specific Melee weapon.', 1, 15);

const assassin = new Ability('Assassin', '+3 DMG from Concealment.', 1, 18);
const vehicleOperation = new Ability('Vehicle Operation*', 'Proficiently operate a complex vehicle.', 1, 18);

const ambidextrous = new Ability('Ambidextrous', 'Off-hand penalty is -1 instead of -3.', 1, 24);
const tough = new Ability('Tough', '+1 HP.', 3, 24);

const selfImprovement = new Ability('Self Improvement*', '+1 to a Trait (max 6).', 3, 30);
const secondChance = new Ability('Second Chance', 'Spend this Ability to avoid Death once.', 9, 30);

const abilities = [
    charismatic,
    favoriteWeapon,
    hyperImmunity,
    packMentality,
    specialize,
    vendetta,
    discipline,
    efficientWork,
    fastDraw,
    fleetFooted,
    quickReload,
    weaponTraining,
    dangerSense,
    fortunate,
    freeRunning,
    honeInstinct,
    multilingual,
    unorthodox,
    fencing,
    martialArts,
    sideStep,
    firmGrip,
    hardHeaded,
    powerfulStrike,
    assassin,
    vehicleOperation,
    ambidextrous,
    tough,
    selfImprovement,
    secondChance
]