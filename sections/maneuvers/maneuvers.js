class Maneuver {
    constructor(name, notes, type) {
        this.name = name;
        this.notes = notes;
        this.type = type;
    }
}

const block = new Maneuver('Block', 'Roll [Melee vs MATK or RATK (if you have a Shield)] for DEF.', 'Defensive');
const dodge = new Maneuver('Dodge', 'Roll [Acrobatics vs MATK or RATK (Throw)] for DEF. <ul><li>Duck: Dodge behind Cover. Material’s DR reduces DMG.</li></ul>', 'Defensive');
const fullDefense = new Maneuver('Full Defense', 'Forego all ATKs on your turn to get a bonus = [Reflex] to all Block and Dodge rolls until your next turn.', 'Defensive');
const hide = new Maneuver('Hide', 'Roll [Stealth vs Perception] to gain Concealment.', 'Defensive');
const protect = new Maneuver('Protect', 'Become the new target of an ATK targeting someone within 1yd of you. You may still Block as normal, but you cannot Dodge the ATK.', 'Defensive');

const aim = new Maneuver('Aim', 'Hold your weapon on target and spend 1AP each rnd for +1 ATK, up to 3AP over 3 or more rnds to get +3 ATK. Defenseless while Aiming.', 'Offensive');
const calledShot = new Maneuver('Called Shot', 'ATK targeting the Head or Limbs. Head ATKs are at -3, do [DMG x 2], and Stun for 1rnd. Limb ATKs are at -1, do [DMG / 2], and cause the enemy to drop a held item (Arms) or be knocked Prone (Legs).', 'Offensive');
const disarm = new Maneuver('Disarm', 'Roll [MATK vs Melee (+[C] if the weapon is used two-handed)]. The weapon flies d6yds. Attacker gets the weapon if they are Unarmed.', 'Offensive');
const dualWield = new Maneuver('Dual-Wield', 'Once per rnd, you may roll ATK or Block for both weapons at a penalty [-1 Primary, -3 Off-hand] for 1AP. Take the best weapon roll.', 'Offensive');
const grab = new Maneuver('Grab', '0DMG MATK to render an enemy Defenseless. Spend 1AP per rnd to retain Grab. Roll [(Acrobatics or Melee) vs Grab] to escape.<ul><li>Attack: Make an ATK against a Grabbed enemy.</li><li>Hold: Block ATKs with Grabbed enemy as a Shield.</li><li>Toss: Throw Grabbed enemy [C] yds, leaving them Prone.</li></ul>', 'Offensive');
const reload = new Maneuver('Reload', 'Replace ammunition in a Ranged weapon.', 'Offensive');
const shove = new Maneuver('Shove', 'Roll [MATK vs C] to push an enemy [C] yds away. 0DMG.', 'Offensive');
const trip = new Maneuver('Trip', 'Roll [MATK vs A] to knock an enemy Prone. 0DMG.', 'Offensive');

const distract = new Maneuver('Distract', 'Roll [Perform(Distract) vs Perception]. Stun target for 1rnd.', 'Social');
const encourage = new Maneuver('Encourage', 'Roll [Leadership vs groups’ total D scores]. The group gets a bonus = [your D] for one specific roll each. A Botch is -1 to all rolls.', 'Social');
const interrogate = new Maneuver('Interrogate', 'Roll [Socialize vs D] to get information out of a subject who does not want to help, but without resorting to violence. Each roll takes d6mins of conversation.<br>If the interrogator Succeeds, the subject gives up a fact (wittingly or unwittingly). If the subject Succeeds, they become hardened against further questioning, imposing a -1 penalty on subsequent attempts. After Fails = [D], the interrogator gives up or the subject cracks and tells everything they know.<ul><li>Torture: Roll [Medicine vs prisoner’s C] once per hour to cause a prisoner d6 Pain to soften the prisoner’s resolve without killing them. Failure does d6 DMG to the prisoner. Roll [D vs D] at the end of each hour (Pain penalty applies). Failure causes -1 Psyche loss. At 0 Psyche, either the torturer cannot do it anymore and gives up, or the prisoner is broken and can be controlled with Leadership or Tame until freed.</li></ul>', 'Social');
const negotiate = new Maneuver('Negotiate', 'If opposed parties are willing to talk out their differences, each side start with a list of negotiable desires.<br>Roll [Socialize vs Socialize] once per desire. Attitude and situational modifiers should be applied by the GN. Success means you get your desire and the opposed negotiator concedes. Either side can choose to concede a desire without rolling.<br>If one side accumulates more than double the concessions of the other, the losing negotiator will feel cheated and end the negotiations. Some desires may be non-negotiable.', 'Social');
const recruit = new Maneuver('Recruit', 'Roll [Leadership vs D] to convince someone to join your side. If they are someone’s follower, roll [Leadership vs Leadership]. Attitude and situational modifiers should be applied by the GN.', 'Social');
const taunt = new Maneuver('Taunt', 'Roll [Leadership vs D]. Provoke the enemy into exclusively attacking you. The degree of Success is a penalty to the loser’s next roll. The enemy is Stunned for 1rnd if [penalty > enemy’s D].', 'Social');