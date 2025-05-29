// Placeholder for handling different overflow behaviors
#ifndef OVERFLOW_HANDLER_H
#define OVERFLOW_HANDLER_H

enum class OverflowBehavior {
    BLOCK,
    DISCARD,
    BUFFER_TO_DISK
};

class OverflowHandler {
public:
    OverflowHandler(OverflowBehavior behavior);
    ~OverflowHandler();

    void handleOverflow(const void* data, int size);

private:
    OverflowBehavior behavior_;
    // TODO: Implement overflow handling logic
};

#endif // OVERFLOW_HANDLER_H
