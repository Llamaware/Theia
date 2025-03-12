// complex.js
(function() {
    "use strict";

    // Helper: Calculate damage based on attack, defense, and a random multiplier.
    function calculateDamage(attack, defense, multiplier) {
        var base = attack - defense;
        if (base < 0) {
            base = 0;
        }
        return Math.floor(base * multiplier);
    }

    // Character constructor
    function Character(name, hp, attack, defense) {
        this.name = name;
        this.hp = hp;
        this.attack = attack;
        this.defense = defense;
        this.inventory = [];
    }

    // Prototype methods
    Character.prototype.takeDamage = function(dmg) {
        this.hp -= dmg;
        if (this.hp < 0) {
            this.hp = 0;
        }
        return this.hp;
    };

    Character.prototype.addItem = function(item) {
        this.inventory.push(item);
    };

    Character.prototype.useItem = function(itemName) {
        for (var i = 0; i < this.inventory.length; i++) {
            if (this.inventory[i].name === itemName) {
                var item = this.inventory.splice(i, 1)[0];
                return item.effect(this);
            }
        }
        return false;
    };

    // Item constructor
    function Item(name, effect) {
        this.name = name;
        this.effect = effect;
    }

    // Battle simulation with nested loops and conditionals.
    function battleSimulation(player, enemy) {
        var rounds = 0;
        while (player.hp > 0 && enemy.hp > 0 && rounds < 100) {
            rounds++;
            var playerDamage = calculateDamage(player.attack, enemy.defense, Math.random() + 0.5);
            var enemyDamage = calculateDamage(enemy.attack, player.defense, Math.random() + 0.5);
            enemy.takeDamage(playerDamage);
            player.takeDamage(enemyDamage);
            if (enemy.hp === 0 || player.hp === 0) break;
        }
        return { rounds: rounds, playerHP: player.hp, enemyHP: enemy.hp };
    }

    // Recursive function for leveling up a character.
    function levelUp(character, levels) {
        if (levels <= 0) return character;
        character.attack += Math.floor(Math.random() * 3 + 1);
        character.defense += Math.floor(Math.random() * 2 + 1);
        character.hp += Math.floor(Math.random() * 10 + 5);
        return levelUp(character, levels - 1);
    }

    // Quest simulation with branching logic.
    function quest(player) {
        var result = {};
        if (player.hp < 20) {
            result.message = "You are too weak to go on the quest.";
            result.success = false;
        } else {
            var challenge = Math.random();
            if (challenge < 0.3) {
                result.message = "You got lost in the dark forest.";
                result.success = false;
            } else if (challenge < 0.6) {
                result.message = "You encountered a wild beast.";
                var beast = new Character("Beast", 50, 8, 4);
                var battle = battleSimulation(player, beast);
                result.battle = battle;
                result.success = (player.hp > beast.hp);
                result.message += result.success ? " You defeated the beast!" : " The beast overpowered you.";
            } else {
                result.message = "You found a hidden treasure.";
                var treasure = new Item("Gold", function(chara) {
                    chara.hp += 10;
                    return true;
                });
                player.addItem(treasure);
                result.success = true;
            }
        }
        return result;
    }

    // Main function: ties everything together.
    function main() {
        var player = new Character("Hero", 100, 15, 10);
        var enemy = new Character("Goblin", 80, 12, 8);
        
        // Level up the player
        player = levelUp(player, 3);
        
        // Run a battle simulation
        var battleResult = battleSimulation(player, enemy);
        
        // Run a quest simulation
        var questResult = quest(player);
        
        // Summarize results in a complex string.
        var summary = "Battle rounds: " + battleResult.rounds + "\n" +
                      "Player HP: " + battleResult.playerHP + "\n" +
                      "Enemy HP: " + battleResult.enemyHP + "\n" +
                      "Quest outcome: " + questResult.message;
        return summary;
    }

    // Expose main for testing
    window.complexTest = main;
})();
