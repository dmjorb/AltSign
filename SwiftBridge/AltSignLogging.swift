//
//  AltSignLogging.swift
//  AltSign
//
//  Created by Magesh K on 28/06/26.
//  Copyright © 2026 SideStore. All rights reserved.
//
import Foundation

public enum AltSignLogging {
    public private(set) static var isLoggingEnabled = false

    public static func setLogging(_ enabled: Bool) {
        isLoggingEnabled = enabled
    }
}

private func getTag(level: String) -> String {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.locale = Locale(identifier: "en_US_POSIX")
    let timestamp = formatter.string(from: Date())
    return "\(timestamp) \(level): "
}

@inline(__always)
public func debugLog(_ text: @autoclosure () -> String) {
    print("\(getTag(level: "DEBUG"))\(text())")
}

@inline(__always)
public func verboseLog(_ text: @autoclosure () -> String) {
    if AltSignLogging.isLoggingEnabled {
        print("\(getTag(level: "TRACE"))\(text())")
    }
}
