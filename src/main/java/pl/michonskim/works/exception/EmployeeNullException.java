package pl.michonskim.works.exception;

import java.time.LocalDateTime;

public class EmployeeNullException extends  RuntimeException {
    private final String message;
    private final LocalDateTime time;

    public EmployeeNullException(String message, LocalDateTime time){
        this.message = message;
        this.time = time;
    }

    @Override
    public String toString() {
        return "EmployeeNotFoundException{" +
                "message='" + message + '\'' +
                ", time=" + time +
                '}';
    }
}
