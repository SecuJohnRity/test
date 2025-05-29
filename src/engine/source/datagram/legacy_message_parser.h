// Placeholder for parsing legacy 4.x messages
#ifndef LEGACY_MESSAGE_PARSER_H
#define LEGACY_MESSAGE_PARSER_H

class LegacyMessageParser {
public:
    LegacyMessageParser();
    ~LegacyMessageParser();

    bool parseMessage(const void* data, int size);

private:
    // TODO: Implement parsing logic
};

#endif // LEGACY_MESSAGE_PARSER_H
